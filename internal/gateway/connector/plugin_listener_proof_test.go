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
	for _, tc := range []struct {
		name string
		opts SetupOpts
		want bool
	}{
		{"managed TCP plugin", SetupOpts{ManagedEnterprise: true, ManagedListenerProof: true}, true},
		{"not requested", SetupOpts{ManagedEnterprise: true}, false},
		{"unmanaged", SetupOpts{ManagedListenerProof: true}, false},
		// Windows keeps TCP even when a socket is named.
		{"hook socket", SetupOpts{ManagedEnterprise: true, ManagedListenerProof: true, ManagedHookSocket: socket}, runtime.GOOS == "windows"},
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
			_, _ = io.WriteString(w, `{"hook_output":{"decision":"allow"}}`)
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
	if asset == "amp-plugin.ts" {
		harness, name = ampListenerProofHarness, "amp-plugin.mts"
	}
	path := writeRenderedPlugin(t, asset, name, templateData{
		APIAddr:         addr,
		TokenFileJS:     javaScriptStringContent(tokenPath),
		ListenerProofJS: proofValue,
		FailMode:        "closed",
		Managed:         true,
	})
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

			// Control: without the proof the impostor is trusted.
			verdict = runListenerProofPlugin(t, tc.asset, addr, tokenPath, false)
			requests = impostorSeen.snapshot()
			if verdict != "allow" || len(requests) != 1 || requests[0].authorization != "Bearer "+credential ||
				!strings.Contains(requests[0].body, "listener-proof-marker") {
				t.Fatalf("control without the proof: verdict %q, requests %+v", verdict, requests)
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
			`const DC_LISTENER_PROOF: string = ""` + "\n", `const DC_LISTENER_PROOF: string = "1"` + "\n", true},
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
