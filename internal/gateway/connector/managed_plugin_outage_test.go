// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// GAP-0465: the docs said the
// administrator's hook_fail_mode: open lets a managed standalone call run
// during a gateway outage for every connector but the Linux and macOS
// Copilot hook. The Amp and OpenCode plugins are rendered with
// DC_FAIL_MODE "closed" for a managed standalone install that has the hook
// socket (Linux and macOS), so they block an outage in every fail mode,
// whatever the administrator chose; the Windows standalone render keeps the
// resolved mode. That is the closed side, so the docs follow the plugins,
// not the other way round. This renders the plugins the way Setup does
// (renderPluginArtifact) for both installed modes and both layouts, runs
// them against a stopped gateway for every installed mode and route.
func TestManagedAmpAndOpenCodeOutageFollowTheDocumentedFailMode(t *testing.T) {
	failModeRE := regexp.MustCompile(`const DC_FAIL_MODE(?:: string)? = "([a-z]*)"`)
	plugins := map[string]*hookOnlyConnector{"amp": NewAMPConnector().hookOnlyConnector, "opencode": NewOpenCodeConnector()}
	for name, c := range plugins {
		for _, layout := range []string{"unix", "windows"} {
			for _, mode := range []string{"open", "closed"} {
				opts := managedPluginOutageOpts(t, name, layout, mode, filepath.Join(testenv.PrivateTempDir(t), "defenseclaw-hook"), "127.0.0.1:18970")
				body, err := c.renderPluginArtifact(opts)
				if err != nil {
					t.Fatalf("%s %s %s: render: %v", name, layout, mode, err)
				}
				want := mode
				if layout == "unix" {
					want = "closed"
					if mode == "open" && ConnectorHookOutage(c).ManagedOpenUnixPerUserRoute == OutageRuns {
						want = "open"
					}
				}
				if got := failModeRE.FindSubmatch(body); got == nil || string(got[1]) != want {
					t.Errorf("%s %s installed mode %q: rendered %q, want DC_FAIL_MODE %q", name, layout, mode, got, want)
				}
			}
		}
	}

	if runtime.GOOS == "windows" {
		t.Log("the plugin runs below use a shell stand-in for the hook binary; the render checks above cover Windows")
	} else {
		nodeForTest(t)
		for name, c := range plugins {
			for _, layout := range []string{"unix", "windows"} {
				for _, mode := range []string{"open", "closed"} {
					root := testenv.PrivateTempDir(t)
					guard := filepath.Join(root, "defenseclaw-hook")
					// The foreign-hook check answers allow; any other call of the
					// hook binary (session facts) gets no answer.
					if err := os.WriteFile(guard, []byte("#!/bin/sh\ncat >/dev/null\ncase \" $* \" in\n  *\" --foreign-hook-check \"*) printf '{\"deny\":false}\\n' ;;\n  *) exit 1 ;;\nesac\n"), 0o700); err != nil {
						t.Fatal(err)
					}
					opts := managedPluginOutageOpts(t, name, layout, mode, guard, stoppedGatewayAddr(t))
					body, err := c.renderPluginArtifact(opts)
					if err != nil {
						t.Fatal(err)
					}
					want := "allow"
					if mode == "closed" || layout == "unix" && ConnectorHookOutage(c).ManagedOpenUnixPerUserRoute == OutageBlocks {
						want = "block"
					}
					for _, got := range runManagedPluginOutage(t, name, root, body) {
						if !strings.HasPrefix(got, want) {
							t.Errorf("%s %s installed mode %q, gateway stopped: %q, want %s", name, layout, mode, got, want)
						}
					}
				}
			}
		}
	}

}

// A Windows standalone Amp plugin may render administrator open for a proven
// stopped service. A gateway that answered 429 is running and has not judged
// the call; neither exhausted 429s nor a failed resend may approve it.
func TestWindowsManagedAmpOpenBlocksAfterRateLimit(t *testing.T) {
	nodeForTest(t)
	for _, tc := range []struct {
		name         string
		retryResult  string
		wantRequests int32
	}{
		{name: "429 until retries end", wantRequests: 4},
		{name: "429 then transport failure", retryResult: "drop", wantRequests: 2},
		{name: "429 then HTTP 500", retryResult: "http500", wantRequests: 2},
		{name: "429 then invalid verdict", retryResult: "invalid", wantRequests: 2},
		{name: "429 then truncated JSON", retryResult: "truncated", wantRequests: 2},
		{name: "429 then usable verdict", retryResult: "allow", wantRequests: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const proofDomain = "defenseclaw.listener-proof.v1\x00amp\x00"
			token := strings.Repeat("a", 64)
			var posts atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/v1/hook-listener-proof":
					mac := hmac.New(sha256.New, []byte(token))
					_, _ = mac.Write([]byte(proofDomain + r.Header.Get("X-DefenseClaw-Listener-Nonce")))
					w.Header().Set("X-DefenseClaw-Listener-Proof", hex.EncodeToString(mac.Sum(nil)))
					w.WriteHeader(http.StatusNoContent)
				case "/api/v1/amp/hook":
					n := posts.Add(1)
					if n == 2 {
						switch tc.retryResult {
						case "allow", "invalid", "truncated":
							w.Header().Set("Content-Type", "application/json")
							body := map[string]string{
								"allow":     `{"action":"allow"}`,
								"invalid":   `{"action":"unknown"}`,
								"truncated": `{"action":`,
							}[tc.retryResult]
							_, _ = w.Write([]byte(body))
							return
						case "http500":
							w.WriteHeader(http.StatusInternalServerError)
							return
						case "drop":
							conn, _, err := w.(http.Hijacker).Hijack()
							if err == nil {
								_ = conn.Close()
							}
							return
						}
					}
					w.Header().Set("Retry-After", "1")
					w.WriteHeader(http.StatusTooManyRequests)
				default:
					t.Errorf("unexpected path %s", r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			t.Cleanup(server.Close)
			root := testenv.PrivateTempDir(t)
			guard := filepath.Join(root, "defenseclaw-hook.exe")
			opts := managedPluginOutageOpts(t, "amp", "windows", "open", guard, strings.TrimPrefix(server.URL, "http://"))
			opts.ManagedListenerProof = true
			plugin, err := NewAMPConnector().renderPluginArtifact(opts)
			if err != nil {
				t.Fatal(err)
			}
			body := string(plugin)
			if !strings.Contains(body, `const DC_FAIL_MODE: string = "open"`) ||
				!strings.Contains(body, `const DC_LISTENER_PROOF: string = "1"`) ||
				!strings.Contains(body, `const DC_HOOK_SOCKET: string = ""`) {
				t.Fatal("plugin is not the Windows standalone open-mode TCP render")
			}
			// Isolate the HTTP delivery path from the foreign-hook executable;
			// the installed render above must still contain its guard.
			guardDecl := `const DC_FOREIGN_GUARD: string = "` + javaScriptStringContent(guard) + `"`
			if strings.Count(body, guardDecl) != 1 {
				t.Fatal("Windows standalone render omitted the foreign-hook guard")
			}
			body = strings.Replace(body, guardDecl, `const DC_FOREIGN_GUARD: string = ""`, 1)
			pluginPath := filepath.Join(root, "defenseclaw.mts")
			if err := os.WriteFile(pluginPath, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			lines := runNodeHarness(t, `
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
globalThis.Bun = { file: (path) => ({ slice: () => ({ text: async () => readFileSync(path, "utf8") }) }) };
const handlers = {};
(await import(pathToFileURL(process.argv[1]).href)).default({
  system: { workspaceRoot: "", executor: { kind: "" }, user: {} },
  helpers: { filePathFromURI: (uri) => uri, isPluginUINotAvailableError: () => true },
  on: (event, handler) => { handlers[event] = handler; },
  activeThread: { current: null },
  ui: { notify: async () => {} },
});
const ctx = { thread: { id: "T", agent: async () => ({ definition: { kind: "builtin-agent", mode: "medium" } }) } };
const result = await handlers["tool.call"]({ thread: { id: "T" }, toolUseID: "U1", tool: "Bash", input: { command: "echo marker" } }, ctx);
console.log(result.action + ":" + (result.message || ""));
`, pluginPath)
			if tc.retryResult == "allow" {
				if len(lines) != 1 || lines[0] != "allow:" {
					t.Fatalf("Windows Amp usable verdict after 429 = %q, want allow", lines)
				}
			} else if len(lines) != 1 || !strings.HasPrefix(lines[0], "reject-and-continue:") || !strings.Contains(lines[0], "429") {
				t.Fatalf("Windows Amp open without a verdict after 429 = %q, want a rate-limit block", lines)
			}
			if got := posts.Load(); got != tc.wantRequests {
				t.Fatalf("gateway received %d tool calls, want %d", got, tc.wantRequests)
			}
		})
	}
}

// Windows standalone OpenCode uses the current plugin with a foreign-hook
// guard and loopback listener proof. A 429 means the gateway has not judged
// the call; a later failure cannot turn that answer into an outage allowance.
func TestWindowsManagedOpenCodeOpenBlocksAfterRateLimit(t *testing.T) {
	nodeForTest(t)
	for _, tc := range []struct {
		name         string
		retryResult  string
		wantRequests int32
	}{
		{name: "429 until retries end", wantRequests: 4},
		{name: "429 then transport failure", retryResult: "drop", wantRequests: 2},
		{name: "429 then HTTP 500", retryResult: "http500", wantRequests: 2},
		{name: "429 then invalid verdict", retryResult: "invalid", wantRequests: 2},
		{name: "429 then truncated JSON", retryResult: "truncated", wantRequests: 2},
		{name: "429 then usable verdict", retryResult: "allow", wantRequests: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var posts atomic.Int32
			server := windowsManagedOpenCodeGateway(t, func(w http.ResponseWriter, n int32) {
				posts.Store(n)
				if n == 2 {
					switch tc.retryResult {
					case "allow", "invalid", "truncated":
						w.Header().Set("Content-Type", "application/json")
						body := map[string]string{
							"allow":     `{"action":"allow"}`,
							"invalid":   `{"action":"unknown"}`,
							"truncated": `{"action":`,
						}[tc.retryResult]
						_, _ = w.Write([]byte(body))
						return
					case "http500":
						w.WriteHeader(http.StatusInternalServerError)
						return
					case "drop":
						conn, _, err := w.(http.Hijacker).Hijack()
						if err == nil {
							_ = conn.Close()
						}
						return
					}
				}
				w.Header().Set("Retry-After", "1")
				w.WriteHeader(http.StatusTooManyRequests)
			})
			lines := runWindowsManagedOpenCode(t, server, "open")
			if tc.retryResult == "allow" {
				if len(lines) != 1 || lines[0] != "allow" {
					t.Fatalf("Windows OpenCode usable verdict after 429 = %q, want allow", lines)
				}
			} else if len(lines) != 1 || !strings.HasPrefix(lines[0], "block:") || !strings.Contains(lines[0], "429") {
				t.Fatalf("Windows OpenCode open without a verdict after 429 = %q, want a rate-limit block", lines)
			}
			if got := posts.Load(); got != tc.wantRequests {
				t.Fatalf("gateway received %d tool calls, want %d", got, tc.wantRequests)
			}
		})
	}
}

// The Windows standalone layout has no hook socket or hook binary, but it
// does have the foreign-hook guard. Its current plugin must reject a complete
// unusable answer and a bare native block in either installed fail mode.
func TestWindowsManagedOpenCodeRejectsUnusableAndBareBlockVerdicts(t *testing.T) {
	nodeForTest(t)
	for _, tc := range []struct {
		name, answer, want string
	}{
		{name: "invalid verdict", answer: `{"action":"unknown"}`, want: "invalid gateway verdict"},
		{name: "bare block", answer: `{"action":"block"}`, want: "missing native deny"},
	} {
		for _, mode := range []string{"open", "closed"} {
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				server := windowsManagedOpenCodeGateway(t, func(w http.ResponseWriter, _ int32) {
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(tc.answer))
				})
				lines := runWindowsManagedOpenCode(t, server, mode)
				if len(lines) != 1 || !strings.HasPrefix(lines[0], "block:") || !strings.Contains(lines[0], tc.want) {
					t.Fatalf("Windows OpenCode %s %s = %q, want a %s block", mode, tc.name, lines, tc.want)
				}
			})
		}
	}
}

func windowsManagedOpenCodeGateway(t *testing.T, answer func(http.ResponseWriter, int32)) *httptest.Server {
	t.Helper()
	const proofDomain = "defenseclaw.listener-proof.v1\x00opencode\x00"
	token := strings.Repeat("a", 64)
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/hook-listener-proof":
			mac := hmac.New(sha256.New, []byte(token))
			_, _ = mac.Write([]byte(proofDomain + r.Header.Get("X-DefenseClaw-Listener-Nonce")))
			w.Header().Set("X-DefenseClaw-Listener-Proof", hex.EncodeToString(mac.Sum(nil)))
			w.WriteHeader(http.StatusNoContent)
		case "/api/v1/opencode/hook":
			var payload struct {
				Event string `json:"hook_event_name"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Errorf("decode OpenCode hook request: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if payload.Event != "tool.execute.before" {
				_, _ = w.Write([]byte(`{"action":"allow"}`))
				return
			}
			answer(w, posts.Add(1))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func runWindowsManagedOpenCode(t *testing.T, server *httptest.Server, mode string) []string {
	t.Helper()
	root := testenv.PrivateTempDir(t)
	guard := filepath.Join(root, "defenseclaw-hook.exe")
	opts := managedPluginOutageOpts(t, "opencode", "windows", mode, guard, strings.TrimPrefix(server.URL, "http://"))
	opts.ManagedListenerProof = true
	plugin, err := NewOpenCodeConnector().renderPluginArtifact(opts)
	if err != nil {
		t.Fatal(err)
	}
	body := string(plugin)
	if !strings.Contains(body, `const DC_FAIL_MODE = "`+mode+`"`) ||
		!strings.Contains(body, `const DC_LISTENER_PROOF = "1"`) ||
		!strings.Contains(body, `const DC_HOOK_SOCKET = ""`) {
		t.Fatal("plugin is not the Windows standalone TCP render")
	}
	// Isolate HTTP delivery from the native guard executable on the test host.
	// The installed render must still carry the administrator-owned guard.
	guardDecl := `const DC_FOREIGN_GUARD = "` + javaScriptStringContent(guard) + `"`
	if strings.Count(body, guardDecl) != 1 {
		t.Fatal("Windows standalone render omitted the foreign-hook guard")
	}
	body = strings.Replace(body, guardDecl, `const DC_FOREIGN_GUARD = ""`, 1)
	return runManagedPluginOutage(t, "opencode", root, []byte(body))
}

// managedPluginOutageOpts are the standalone Setup options of one layout:
// "unix" carries the hook socket and the administrator-owned hook binary
// (enterprise_hooks_standalone_unix.go), "windows" only the foreign-hook
// guard and the TCP gateway (install_windows.go).
func managedPluginOutageOpts(t *testing.T, name, layout, mode, guard, apiAddr string) SetupOpts {
	t.Helper()
	root := testenv.PrivateTempDir(t)
	opts := SetupOpts{
		DataDir:                filepath.Join(root, "defenseclaw"),
		APIAddr:                apiAddr,
		ManagedEnterprise:      true,
		HookFailMode:           mode,
		ForeignHookGuardBinary: guard,
	}
	if layout == "unix" {
		opts.ManagedHookSocket = filepath.Join(root, "hook.sock") // never created: the service is stopped
		opts.ManagedHookBinary = guard
		opts.ManagedServiceUID = os.Getuid()
	}
	token, err := HookAPITokenFilePath(opts.DataDir, name)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(token), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(token, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return opts
}

// stoppedGatewayAddr is a loopback address nothing listens on.
func stoppedGatewayAddr(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

// runManagedPluginOutage loads the rendered plugin and sends it one call per
// blockable event, printing "allow" or "block:<reason>" for each.
func runManagedPluginOutage(t *testing.T, name, root string, body []byte) []string {
	t.Helper()
	file := filepath.Join(root, "defenseclaw.mjs")
	harness := managedOpenCodeOutageHarness
	if name == "amp" {
		file, harness = filepath.Join(root, "defenseclaw.mts"), managedAmpOutageHarness
	}
	if err := os.WriteFile(file, body, 0o600); err != nil {
		t.Fatal(err)
	}
	lines := runNodeHarness(t, harness, file)
	if want := map[string]int{"amp": 2, "opencode": 1}[name]; len(lines) != want {
		t.Fatalf("%s: harness printed %q, want %d verdicts", name, lines, want)
	}
	return lines
}

const managedOpenCodeOutageHarness = `
import { pathToFileURL } from "node:url";
const href = pathToFileURL(process.argv[1]).href;
const loaded = await import(href);
const plugin = await loaded.DefenseClaw({ directory: "", client: {} });
await plugin.config({ plugin_origins: [{ spec: href }], mcp: {} });
try {
  await plugin["tool.execute.before"]({ tool: "bash", sessionID: "S", messageID: "M", callID: "C1" }, { args: { command: "echo marker" } });
  console.log("allow");
} catch (error) {
  console.log("block:" + String(error && error.message || error));
}
`

const managedAmpOutageHarness = `
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
// Amp runs plugins on Bun; the plugin reads its credential with Bun.file.
globalThis.Bun = { file: (path) => ({ slice: () => ({ text: async () => readFileSync(path, "utf8") }) }) };
const loaded = await import(pathToFileURL(process.argv[1]).href);
const handlers = {};
loaded.default({
  system: { workspaceRoot: "", executor: { kind: "" }, user: {} },
  helpers: { filePathFromURI: (uri) => uri, isPluginUINotAvailableError: () => true },
  on: (event, handler) => { handlers[event] = handler; },
  activeThread: { current: null },
  ui: { notify: async () => {} },
});
const ctx = { thread: { id: "T", agent: async () => ({ definition: { kind: "builtin-agent", mode: "medium" } }) }, ui: { notify: async () => {} } };
const call = await handlers["tool.call"]({ thread: { id: "T" }, toolUseID: "U1", tool: "Bash", input: { command: "echo marker" } }, ctx);
console.log(call.action === "allow" ? "allow" : "block:" + call.message);
const result = await handlers["tool.result"]({ thread: { id: "T" }, toolUseID: "U1", tool: "Bash", input: { command: "echo marker" }, output: "marker", status: "done" }, ctx);
console.log(result ? "block:" + result.error : "allow");
`
