// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// ampSocketToolCallHarness runs one tool.call through a rendered Amp plugin.
// Amp's runtime is Bun, whose fetch takes a unix option for the managed hook
// socket; the harness gives Node that option over node:http, so a connection
// failure surfaces with its socket error code as it would under Bun.
const ampSocketToolCallHarness = `
import { pathToFileURL } from "node:url";
import { request } from "node:http";
globalThis.Bun = {};
const nodeFetch = globalThis.fetch;
globalThis.fetch = (url, init = {}) => {
  if (!init.unix) return nodeFetch(url, init);
  return new Promise((resolve, reject) => {
    const req = request({ socketPath: init.unix, path: new URL(url).pathname, method: init.method || "GET", headers: init.headers }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve(new Response(Buffer.concat(chunks), {
        status: res.statusCode,
        headers: Object.fromEntries(Object.entries(res.headers).filter(([, value]) => typeof value === "string")),
      })));
      res.on("error", reject);
    });
    req.on("error", reject);
    if (init.signal) init.signal.addEventListener("abort", () => req.destroy(new Error("aborted")), { once: true });
    req.end(init.body);
  });
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
const ctx = { thread: { id: "T", agent: async () => ({ definition: { kind: "builtin-agent", mode: "medium" } }) } };
const result = await handlers["tool.call"]({ thread: { id: "T" }, toolUseID: "U1", tool: "Bash", input: { cmd: "echo marker" } }, ctx);
console.log(result.action === "allow" ? "allow" : "block:" + (result.message || ""));
`

// A managed administrator's hook_fail_mode open lets an in-agent plugin
// bridge (Amp, OpenCode) run a tool call during an outage only when the
// hook socket is proven absent from its verified directories, the native
// hook's rule (validateStandaloneHookSocketPath). DEFENSECLAW_STRICT_AVAILABILITY
// closes that outage too, and an installed closed mode closes every case.
// A missing socket directory or parent, an untrusted directory, a stale
// socket that refuses the connection after verification and a path that
// is not a socket prove nothing about who would answer, so they block.
func TestManagedPluginOutageOpenNeedsAVerifiedSocketAbsence(t *testing.T) {
	nodeForTest(t)
	type layout struct {
		socket   string
		answered *atomic.Int32
	}
	setups := map[string]func(t *testing.T, root string) layout{
		"socket absent": func(t *testing.T, root string) layout {
			return layout{socket: filepath.Join(mkTrustedDir(t, root, "run"), "hook.sock")}
		},
		"socket directory absent": func(t *testing.T, root string) layout {
			return layout{socket: filepath.Join(root, "run", "hook.sock")}
		},
		"socket directory parent absent": func(t *testing.T, root string) layout {
			return layout{socket: filepath.Join(root, "gone", "run", "hook.sock")}
		},
		"untrusted socket directory": func(t *testing.T, root string) layout {
			dir := mkTrustedDir(t, root, "run")
			if err := os.Chmod(dir, 0o777); err != nil {
				t.Fatal(err)
			}
			return layout{socket: filepath.Join(dir, "hook.sock")}
		},
		"stale socket refuses": func(t *testing.T, root string) layout {
			socket := filepath.Join(mkTrustedDir(t, root, "run"), "hook.sock")
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			listener.SetUnlinkOnClose(false)
			_ = listener.Close()
			return layout{socket: socket}
		},
		"not a socket": func(t *testing.T, root string) layout {
			socket := filepath.Join(mkTrustedDir(t, root, "run"), "hook.sock")
			if err := os.WriteFile(socket, nil, 0o644); err != nil {
				t.Fatal(err)
			}
			return layout{socket: socket}
		},
		// The control: the harness reaches a live gateway over the socket.
		"live socket allows": func(t *testing.T, root string) layout {
			socket := filepath.Join(mkTrustedDir(t, root, "run"), "hook.sock")
			listener, err := net.Listen("unix", socket)
			if err != nil {
				t.Fatal(err)
			}
			answered := new(atomic.Int32)
			server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				answered.Add(1)
				_ = json.NewEncoder(w).Encode(map[string]any{"action": "allow", "hook_output": map[string]any{"decision": "allow"}})
			})}
			go func() { _ = server.Serve(listener) }()
			t.Cleanup(func() { _ = server.Close() })
			return layout{socket: socket, answered: answered}
		},
	}
	for _, plugin := range []string{"amp-plugin.ts", "opencode-plugin.js"} {
		for name, setup := range setups {
			for _, tc := range []struct{ installed, strict string }{
				{"open", ""}, {"open", "1"}, {"open", "yes"}, {"closed", ""},
			} {
				t.Run(plugin+"/"+name+"/"+tc.installed+"/strict="+tc.strict, func(t *testing.T) {
					t.Setenv("DEFENSECLAW_STRICT_AVAILABILITY", tc.strict)
					// Unix socket paths are length-limited; keep the root short.
					root, err := os.MkdirTemp("/tmp", "dcso")
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = os.RemoveAll(root) })
					if err := os.Chmod(root, 0o755); err != nil {
						t.Fatal(err)
					}
					l := setup(t, root)
					data := templateData{
						APIAddr:      "127.0.0.1:9",
						TokenFileJS:  javaScriptStringContent(filepath.Join(testenv.PrivateTempDir(t), "hooks", ".hook.token")),
						FailMode:     tc.installed,
						HookSocketJS: javaScriptStringContent(l.socket),
						ServiceUID:   os.Getuid(),
						Managed:      true,
					}
					var lines []string
					if plugin == "amp-plugin.ts" {
						lines = runNodeHarness(t, ampSocketToolCallHarness, writeRenderedPlugin(t, plugin, "defenseclaw.mts", data))
					} else {
						lines = runOpenCodePluginHarness(t, data, 1)
					}
					if len(lines) == 0 {
						t.Fatal("no verdict")
					}
					wantAllow := name == "live socket allows" || (name == "socket absent" && tc.installed == "open" && tc.strict == "")
					if allowed := lines[0] == "allow"; allowed != wantAllow {
						t.Fatalf("verdict %q, want allowed=%v", lines[0], wantAllow)
					}
					if l.answered != nil && l.answered.Load() == 0 {
						t.Fatal("the live gateway was never asked")
					}
					if !wantAllow && !strings.HasPrefix(lines[0], "block:") {
						t.Fatalf("verdict %q is neither allow nor block", lines[0])
					}
				})
			}
		}
	}
}

// mkTrustedDir creates root/name owned by the test account (standing in for
// the gateway service account) and writable only by it.
func mkTrustedDir(t *testing.T, root, name string) string {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}
