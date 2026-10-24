// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// Only a managed plugin that asks for the listener proof and keeps the TCP
// transport renders it; a unix hook socket verifies its owner instead.
func TestManagedPluginListenerProofOnlyForManagedTCPPlugins(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "hook.sock")
	guard := filepath.Join(t.TempDir(), "defenseclaw-hook")
	for _, tc := range []struct {
		name string
		opts SetupOpts
		want bool
	}{
		{"managed TCP plugin", SetupOpts{ManagedEnterprise: true, ManagedListenerProof: true, ForeignHookGuardBinary: guard}, true},
		{"not requested", SetupOpts{ManagedEnterprise: true, ForeignHookGuardBinary: guard}, false},
		{"unmanaged", SetupOpts{ManagedListenerProof: true}, false},
		// Windows keeps TCP even when a socket is named.
		{"hook socket", SetupOpts{ManagedEnterprise: true, ManagedListenerProof: true, ManagedHookSocket: socket, ForeignHookGuardBinary: guard}, runtime.GOOS == "windows"},
	} {
		if got := managedPluginListenerProof(tc.opts); got != tc.want {
			t.Errorf("%s: listener proof = %v, want %v", tc.name, got, tc.want)
		}
		want := ""
		if tc.want {
			want = "1"
		}
		if got := managedPluginListenerProofJS(tc.opts); got != want {
			t.Errorf("%s: rendered value = %q, want %q", tc.name, got, want)
		}
	}
}

// listenerProofRequest is one request a test listener received.
type listenerProofRequest struct {
	method        string
	path          string
	authorization string
	body          string
}

type listenerProofRecorder struct {
	mu       sync.Mutex
	requests []listenerProofRequest
}

func (r *listenerProofRecorder) record(req *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(req.Body, 1<<20))
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests = append(r.requests, listenerProofRequest{
		method:        req.Method,
		path:          req.URL.Path,
		authorization: req.Header.Get("Authorization"),
		body:          string(body),
	})
}

func (r *listenerProofRecorder) snapshot() []listenerProofRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := append([]listenerProofRequest(nil), r.requests...)
	r.requests = nil
	return out
}

// newImpostorListener answers like a user-owned process holding the gateway
// port: an arbitrary "proof" and an allow verdict for every hook request.
func newImpostorListener(t *testing.T, recorder *listenerProofRecorder) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		recorder.record(req)
		switch req.URL.Path {
		case UserScopedListenerProofPath:
			w.Header().Set(UserScopedListenerProofHeader, strings.Repeat("0", 64))
			w.WriteHeader(http.StatusNoContent)
		case "/api/v1/amp/hook":
			_, _ = io.WriteString(w, `{"action":"allow"}`)
		default:
			_, _ = io.WriteString(w, `{"action":"allow","hook_output":{"decision":"allow"}}`)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

const openCodeListenerProofHarness = `
import { pathToFileURL } from "node:url";
const loaded = await import(pathToFileURL(process.argv[1]).href);
const plugin = await loaded.DefenseClaw({ directory: "" });
try {
  await plugin["tool.execute.before"](
    { tool: "Bash", sessionID: "S", messageID: "M", callID: "C" },
    { args: { command: "printf listener-proof-marker" } },
  );
  console.log("allow");
} catch (error) {
  console.log("block:" + String(error && error.message || error));
}
`

// The Amp plugin runs under Bun, which provides Bun.file; the harness gives
// node the same small reader and a minimal plugin API.
const ampListenerProofHarness = `
import { pathToFileURL } from "node:url";
import { readFile } from "node:fs/promises";
globalThis.Bun = {
  file: (path) => ({ slice: (start, end) => ({ text: async () => (await readFile(path, "utf8")).slice(start, end) }) }),
};
const loaded = await import(pathToFileURL(process.argv[1]).href);
const handlers = {};
loaded.default({
  system: { workspaceRoot: "", executor: { kind: "" }, user: {} },
  helpers: { filePathFromURI: (uri) => uri, isPluginUINotAvailableError: () => true },
  on: (event, handler) => { handlers[event] = handler; },
  activeThread: { current: null },
  ui: { notify: async () => {} },
});
const result = await handlers["tool.call"](
  { thread: { id: "T" }, toolUseID: "U", tool: "Bash", input: { command: "printf listener-proof-marker" } },
  { thread: { agent: async () => { throw new Error("no agent"); } }, ui: { confirm: async () => false } },
);
console.log(result && result.action === "allow" ? "allow" : "block:" + String(result && result.message));
`

// runListenerProofPlugin renders asset against addr with the listener proof
// on or off, runs one pre-tool call in node, and returns its verdict.
func runListenerProofPlugin(t *testing.T, asset, addr, tokenPath string, proof bool) string {
	t.Helper()
	proofValue := ""
	if proof {
		proofValue = "1"
	}
	harness, name := openCodeListenerProofHarness, "opencode-plugin.mjs"
	if strings.HasPrefix(asset, "amp-plugin") {
		harness, name = ampListenerProofHarness, "amp-plugin.mts"
	}
	data := templateData{
		APIAddr:         addr,
		TokenFileJS:     javaScriptStringContent(tokenPath),
		ListenerProofJS: proofValue,
		FailMode:        "closed",
		Managed:         true,
	}
	path := filepath.Join(testenv.PrivateTempDir(t), name)
	if err := os.WriteFile(path, []byte(renderPluginAssetForTest(t, asset, data)), 0o600); err != nil {
		t.Fatal(err)
	}
	return strings.Join(runNodeHarness(t, harness, path), "\n")
}

// A Windows standalone plugin reaches the gateway over loopback TCP. A local
// user who holds the port while the gateway restarts must receive neither
// the user's credential nor the tool call, and must not be able to answer
// with a verdict: the plugin asks for the listener proof first, the
// impostor cannot produce it, and the tool call fails closed. Without the
// proof the impostor receives the bearer and its allow is trusted, which is
// what the proof prevents.
func TestPluginListenerProofKeepsTheCredentialFromAnImpostor(t *testing.T) {
	nodeForTest(t)
	const key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const sid = "S-1-5-21-1111-2222-3333-1001"
	for _, tc := range []struct{ asset, connector string }{
		{"opencode-plugin.js", "opencode"},
		{"amp-plugin.ts", "amp"},
	} {
		t.Run(tc.connector, func(t *testing.T) {
			credential, err := UserScopedHookAPIToken(key, tc.connector, sid)
			if err != nil {
				t.Fatal(err)
			}
			root := testenv.PrivateTempDir(t)
			tokenPath := filepath.Join(root, ".hook-"+tc.connector+".token")
			if err := os.WriteFile(tokenPath, []byte(credential+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}

			impostorSeen := &listenerProofRecorder{}
			impostor := newImpostorListener(t, impostorSeen)
			addr := strings.TrimPrefix(impostor.URL, "http://")
			verdict := runListenerProofPlugin(t, tc.asset, addr, tokenPath, true)
			if !strings.HasPrefix(verdict, "block:DefenseClaw hook failed closed") ||
				!strings.Contains(verdict, "did not prove its identity") {
				t.Fatalf("impostor listener: verdict %q, want a fail-closed block", verdict)
			}
			requests := impostorSeen.snapshot()
			if len(requests) != 1 || requests[0].path != UserScopedListenerProofPath || requests[0].method != http.MethodGet {
				t.Fatalf("impostor must see only the proof request, saw %+v", requests)
			}
			if request := requests[0]; request.authorization != "" || request.body != "" ||
				strings.Contains(request.path, credential) {
				t.Fatalf("impostor received a credential or payload: %+v", request)
			}

			// A host render missing both the native account check and the
			// listener proof must refuse its TCP fallback as well.
			verdict = runListenerProofPlugin(t, tc.asset, addr, tokenPath, false)
			requests = impostorSeen.snapshot()
			if !strings.HasPrefix(verdict, "block:DefenseClaw hook failed closed") ||
				!strings.Contains(verdict, "no account proof") || len(requests) != 0 {
				t.Fatalf("unguarded TCP fallback: verdict %q, requests %+v", verdict, requests)
			}

		})
	}
}

// The per-user plugin must consult the native account check before posting a
// bearer or an event. A stopped gateway lets a peer bind the same port; a
// failed check must keep that peer from seeing either value.
func TestPerUserPluginsCheckPeerBeforeSending(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Node harness uses a POSIX stub binary; Windows ownership is covered by hookexec")
	}
	node := nodeForTest(t)
	for _, tc := range []struct{ asset, connector string }{
		{"opencode-plugin.js", "opencode"},
		{"amp-plugin.ts", "amp"},
	} {
		t.Run(tc.connector, func(t *testing.T) {
			const credential = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
			root := testenv.PrivateTempDir(t)
			binary := filepath.Join(root, ".local", "bin", "defenseclaw-gateway")
			marker := filepath.Join(root, "peer-check-args")
			if err := os.MkdirAll(filepath.Dir(binary), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(binary, []byte("#!/bin/sh\nprintf '%s\\n' \"$*\" > \"$DC_PEER_MARKER\"\nexit 1\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			tokenPath := filepath.Join(root, ".hook-"+tc.connector+".token")
			if err := os.WriteFile(tokenPath, []byte(credential+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			recorder := &listenerProofRecorder{}
			impostor := newImpostorListener(t, recorder)
			addr := strings.TrimPrefix(impostor.URL, "http://")
			harness, name := openCodeListenerProofHarness, "opencode-plugin.mjs"
			if tc.connector == "amp" {
				harness, name = ampListenerProofHarness, "amp-plugin.mts"
			}
			plugin := filepath.Join(testenv.PrivateTempDir(t), name)
			body := renderPluginAssetForTest(t, tc.asset, templateData{
				APIAddr: addr, TokenFileJS: javaScriptStringContent(tokenPath), FailMode: "closed",
			})
			if err := os.WriteFile(plugin, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), nodeHarnessTimeout)
			defer cancel()
			cmd := exec.CommandContext(ctx, node, "--input-type=module", "-e", harness, plugin)
			cmd.Env = append(os.Environ(), "HOME="+root, "DC_PEER_MARKER="+marker)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("node: %v: %s", err, output)
			}
			if !strings.Contains(string(output), "block:") {
				t.Fatalf("peer check did not fail closed: %s", output)
			}
			if got := recorder.snapshot(); len(got) != 0 {
				t.Fatalf("unproven peer received a request: %+v", got)
			}
			if data, err := os.ReadFile(marker); err != nil || string(data) != "hook-post --api-addr "+addr+"\n" {
				t.Fatalf("native post was not invoked for %s: %q, %v", addr, data, err)
			}
			openPlugin := filepath.Join(testenv.PrivateTempDir(t), name)
			openBody := renderPluginAssetForTest(t, tc.asset, templateData{
				APIAddr: addr, TokenFileJS: javaScriptStringContent(tokenPath), FailMode: "open",
			})
			if err := os.WriteFile(openPlugin, []byte(openBody), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd = exec.CommandContext(ctx, node, "--input-type=module", "-e", harness, openPlugin)
			cmd.Env = append(os.Environ(), "HOME="+root, "DC_PEER_MARKER="+marker)
			output, err = cmd.CombinedOutput()
			if err != nil || !strings.Contains(string(output), "block:") {
				t.Fatalf("unproven peer in open mode did not fail closed: %v: %s", err, output)
			}
			if got := recorder.snapshot(); len(got) != 0 {
				t.Fatalf("open mode sent data to unproven peer: %+v", got)
			}
		})
	}
}

// A successful check on one socket says nothing about the next connection:
// the gateway can stop and a peer account can bind before JavaScript posts.
// The native helper must own the post and verify its very own connected socket.
func TestPerUserPluginsDoNotPostAfterTheCheckedListenerChanges(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Node harness uses a POSIX stub binary; Windows socket ownership is covered by hookexec")
	}
	node := nodeForTest(t)
	for _, tc := range []struct{ asset, connector string }{
		{"opencode-plugin.js", "opencode"},
		{"amp-plugin.ts", "amp"},
	} {
		t.Run(tc.connector, func(t *testing.T) {
			root := testenv.PrivateTempDir(t)
			binary := filepath.Join(root, ".local", "bin", "defenseclaw-gateway")
			if err := os.MkdirAll(filepath.Dir(binary), 0o700); err != nil {
				t.Fatal(err)
			}
			// A separate preflight would pass; a post owned by the native
			// helper fails because the destination changed before it dialed.
			if err := os.WriteFile(binary, []byte("#!/bin/sh\n[ \"$1\" = hook-verify-peer ] && exit 0\nexit 1\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			tokenPath := filepath.Join(root, ".hook-"+tc.connector+".token")
			if err := os.WriteFile(tokenPath, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			recorder := &listenerProofRecorder{}
			peer := newImpostorListener(t, recorder)
			addr := strings.TrimPrefix(peer.URL, "http://")
			harness, name := openCodeListenerProofHarness, "opencode-plugin.mjs"
			if tc.connector == "amp" {
				harness, name = ampListenerProofHarness, "amp-plugin.mts"
			}
			plugin := filepath.Join(testenv.PrivateTempDir(t), name)
			body := renderPluginAssetForTest(t, tc.asset, templateData{
				APIAddr: addr, TokenFileJS: javaScriptStringContent(tokenPath), FailMode: "closed",
			})
			if err := os.WriteFile(plugin, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), nodeHarnessTimeout)
			defer cancel()
			cmd := exec.CommandContext(ctx, node, "--input-type=module", "-e", harness, plugin)
			cmd.Env = append(os.Environ(), "HOME="+root)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("node: %v: %s", err, output)
			}
			if !strings.Contains(string(output), "block:") {
				t.Fatalf("peer replacement was trusted: %s", output)
			}
			if seen := recorder.snapshot(); len(seen) != 0 {
				t.Fatalf("peer replacement received credential or event: %+v", seen)
			}
		})
	}
}

// The native helper receives the bearer on stdin. A peer-writable indirection
// to another executable must be rejected before execFileSync gets that input.
func TestPerUserPluginsRejectSymlinkedNativePostBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Node harness uses a POSIX stub binary")
	}
	node := nodeForTest(t)
	for _, tc := range []struct{ asset, connector string }{
		{"opencode-plugin.js", "opencode"},
		{"amp-plugin.ts", "amp"},
	} {
		t.Run(tc.connector, func(t *testing.T) {
			root := testenv.PrivateTempDir(t)
			binary := filepath.Join(root, ".local", "bin", "defenseclaw-gateway")
			if err := os.MkdirAll(filepath.Dir(binary), 0o700); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(root, "stolen-input")
			foreign := filepath.Join(root, "foreign-helper")
			if err := os.WriteFile(foreign, []byte("#!/bin/sh\n[ \"$1\" = hook-post ] && cat > \"$DC_PEER_MARKER\"\nexit 1\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(foreign, binary); err != nil {
				t.Fatal(err)
			}
			credential := strings.Repeat("a", 64)
			tokenPath := filepath.Join(root, ".hook-"+tc.connector+".token")
			if err := os.WriteFile(tokenPath, []byte(credential+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			harness, name := openCodeListenerProofHarness, "opencode-plugin.mjs"
			if tc.connector == "amp" {
				harness, name = ampListenerProofHarness, "amp-plugin.mts"
			}
			plugin := filepath.Join(testenv.PrivateTempDir(t), name)
			body := renderPluginAssetForTest(t, tc.asset, templateData{
				APIAddr: "127.0.0.1:18970", TokenFileJS: javaScriptStringContent(tokenPath), FailMode: "closed",
			})
			if err := os.WriteFile(plugin, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), nodeHarnessTimeout)
			defer cancel()
			cmd := exec.CommandContext(ctx, node, "--input-type=module", "-e", harness, plugin)
			cmd.Env = append(os.Environ(), "HOME="+root, "DC_PEER_MARKER="+marker)
			output, err := cmd.CombinedOutput()
			if err != nil || !strings.Contains(string(output), "block:") {
				t.Fatalf("symlinked helper did not fail closed: %v: %s", err, output)
			}
			if data, err := os.ReadFile(marker); err == nil {
				t.Fatalf("symlinked helper received stdin: %q", data)
			} else if !os.IsNotExist(err) {
				t.Fatal(err)
			}
		})
	}
}

// A managed plugin rendered without a safeguard its install requires (the
// Amp foreign-hook guard, the Amp and OpenCode listener proof) fails
// verification, so the guardian repairs it; the render that carries it
// verifies, and the per-user render verifies without it.
func TestManagedPluginVerificationRequiresEachRenderedSafeguard(t *testing.T) {
	guard := testForeignHookGuardBinary()
	for _, tc := range []struct {
		name, connector string
		require         func(*SetupOpts)
		off, on         string
		// patch turns the safeguard on in the per-user file; otherwise
		// Setup renders the file again with the required options.
		patch bool
	}{
		{"amp foreign-hook guard", "amp", func(o *SetupOpts) { o.ForeignHookGuardBinary = guard },
			`const DC_FOREIGN_GUARD: string = ""` + "\n", `const DC_FOREIGN_GUARD: string = "` + javaScriptStringContent(guard) + `"` + "\n", true},
		{"amp listener proof", "amp", func(o *SetupOpts) { o.ManagedListenerProof = true },
			`const DC_LISTENER_PROOF: string = ""` + "\n", `const DC_LISTENER_PROOF: string = "1"` + "\n", false},
		{"opencode listener proof", "opencode", func(o *SetupOpts) { o.ManagedListenerProof = true },
			`const DC_LISTENER_PROOF = "";` + "\n", `const DC_LISTENER_PROOF = "1";` + "\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := testenv.PrivateTempDir(t)
			base := SetupOpts{DataDir: filepath.Join(root, "defenseclaw"), APIAddr: "127.0.0.1:18970", APIToken: "tok-" + tc.connector}
			var conn Connector
			var pluginPath string
			var opts SetupOpts
			if tc.connector == "amp" {
				pluginPath = filepath.Join(root, ".config", "amp", "plugins", "defenseclaw.ts")
				previous := AMPPluginPathOverride
				AMPPluginPathOverride = pluginPath
				t.Cleanup(func() { AMPPluginPathOverride = previous })
				conn, opts = NewAMPConnector(), prepareAmpSetupOptsForTest(t, base)
			} else {
				pluginPath = filepath.Join(root, ".config", "opencode", "plugins", "defenseclaw.js")
				previous := OpenCodePluginPathOverride
				OpenCodePluginPathOverride = pluginPath
				t.Cleanup(func() { OpenCodePluginPathOverride = previous })
				conn, opts = NewOpenCodeConnector(), prepareOpenCodeSetupOptsForTest(t, base)
			}
			if err := conn.Setup(context.Background(), opts); err != nil {
				t.Fatalf("Setup: %v", err)
			}
			data, err := os.ReadFile(pluginPath)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(data), tc.off) {
				t.Fatalf("a per-user render must leave the safeguard off (%q)", tc.off)
			}
			if present, err := OwnedHooksPresent(conn, opts); err != nil || !present {
				t.Fatalf("the per-user plugin verifies without the safeguard: %v %v", present, err)
			}
			required := opts
			required.ManagedEnterprise = true
			required.ForeignHookGuardBinary = guard
			tc.require(&required)
			if present, err := OwnedHooksPresent(conn, required); err != nil || present {
				t.Fatalf("a plugin without the safeguard must fail verification: %v %v", present, err)
			}
			if tc.patch {
				err = os.WriteFile(pluginPath, []byte(strings.Replace(string(data), tc.off, tc.on, 1)), 0o600)
			} else {
				err = conn.Setup(context.Background(), required)
			}
			if err != nil {
				t.Fatal(err)
			}
			if data, _ := os.ReadFile(pluginPath); !strings.Contains(string(data), tc.on) {
				t.Fatalf("the plugin does not carry %q", tc.on)
			}
			if present, err := OwnedHooksPresent(conn, required); err != nil || !present {
				t.Fatalf("a plugin carrying the safeguard verifies: %v %v", present, err)
			}
		})
	}
}
