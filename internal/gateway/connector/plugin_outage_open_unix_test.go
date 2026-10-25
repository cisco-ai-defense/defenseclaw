// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const openCodeOutageHarness = `
import { pathToFileURL } from "node:url";
const toasts = [];
const href = pathToFileURL(process.argv[1]).href;
const plugin = await (await import(href)).DefenseClaw({ directory: "", client: { tui: { showToast: async (arg) => { toasts.push(arg && arg.body ? arg.body.message : ""); return true; } } } });
await plugin.config({ plugin_origins: [{ spec: href }], mcp: {} });
let verdict = "allow";
try {
  await plugin["tool.execute.before"]({ tool: "bash", sessionID: "S", messageID: "M", callID: "C" }, { args: { command: "echo marker" } });
} catch (error) {
  verdict = "block:" + String(error && error.message || error);
}


await new Promise((resolve) => setTimeout(resolve, 50));
console.log(JSON.stringify({ verdict, notices: toasts }));
`

const ampOutageHarness = `
import { pathToFileURL } from "node:url";
globalThis.Bun = { file: () => ({ slice: () => ({ text: async () => "a".repeat(64) + "\n" }) }) };
const handlers = new Map();
const notices = [];
const amp = {
  system: { workspaceRoot: "", executor: { kind: "local" }, user: {} },
  helpers: { filePathFromURI: value => value, isPluginUINotAvailableError: () => false },
  activeThread: { current: { id: "S" } },
  ui: { notify: async (message) => { notices.push(message); } },
  on: (event, handler) => { handlers.set(event, handler); return { unsubscribe() {} }; },
};
(await import(pathToFileURL(process.argv[1]).href)).default(amp);
const ctx = { thread: { agent: async () => ({ definition: { kind: "builtin-agent", mode: "medium" } }) }, ui: { confirm: async () => true, notify: async (message) => { notices.push(message); } } };
const call = await handlers.get("tool.call")({ thread: { id: "S" }, toolUseID: "C", tool: "Bash", input: { command: "echo marker" } }, ctx);
const verdict = call.action === "allow" ? "allow" : "block:" + (call.message || call.action);
console.log(JSON.stringify({ verdict, notices }));
`

// Every command and target key of an oversized plugin call reaches the
// gateway's bounded review, before or after a long value (Amp Bash "cmd",
// OpenCode "command", a write's file path after its content).
func TestPerUserPluginOversizedProtectedPrefixGetsGatewayBlock(t *testing.T) {
	nodeForTest(t)
	const pad = `"x".repeat(1100000)`
	// Loop round 2: context fields that use up the context-head budget, and
	// command values that together exceed the whole-value budget.
	const notes = `...Object.fromEntries(Array.from({ length: 40 }, (_, i) => ["note" + i, "z".repeat(9000)])), `
	const overBudget = `patch: "q".repeat(600000), diff: "r".repeat(400000), `
	for _, plugin := range []struct {
		asset, name, connector, harness, input string
		local                                  bool // no review: the plugin blocks locally
	}{
		{"opencode-plugin.js", "defenseclaw.mjs", "opencode", openCodeOutageHarness, `command: "cat /home/user/.ssh/authorized_keys " + ` + pad, true},
		{"opencode-plugin.js", "defenseclaw.mjs", "opencode", openCodeOutageHarness, `description: ` + pad + `, command: "cat /home/user/.ssh/authorized_keys"`, false},
		{"opencode-plugin.js", "defenseclaw.mjs", "opencode", openCodeOutageHarness, `content: ` + pad + `, filePath: "/home/user/.ssh/authorized_keys"`, false},
		{"opencode-plugin.js", "defenseclaw.mjs", "opencode", openCodeOutageHarness, `description: ` + pad + `, ` + notes + `command: "cat /home/user/.ssh/authorized_keys"`, false},
		{"opencode-plugin.js", "defenseclaw.mjs", "opencode", openCodeOutageHarness, overBudget + notes + `command: "cat /home/user/.ssh/authorized_keys"`, true},
		{"amp-plugin.ts", "defenseclaw.mts", "amp", ampOutageHarness, `command: "cat /home/user/.ssh/authorized_keys " + ` + pad, true},
		{"amp-plugin.ts", "defenseclaw.mts", "amp", ampOutageHarness, `cmd: "cat /home/user/.ssh/authorized_keys", description: ` + pad, false},
		{"amp-plugin.ts", "defenseclaw.mts", "amp", ampOutageHarness, `content: ` + pad + `, path: "/home/user/.ssh/authorized_keys"`, false},
		{"amp-plugin.ts", "defenseclaw.mts", "amp", ampOutageHarness, `description: ` + pad + `, ` + notes + `cmd: "cat /home/user/.ssh/authorized_keys"`, false},
		{"amp-plugin.ts", "defenseclaw.mts", "amp", ampOutageHarness, overBudget + notes + `cmd: "cat /home/user/.ssh/authorized_keys"`, true},
	} {
		name := strings.SplitN(plugin.input, ":", 2)[0]
		if strings.HasPrefix(plugin.input, overBudget) {
			name = "over budget"
		} else if strings.Contains(plugin.input, "note") {
			name += " then notes"
		}
		t.Run(plugin.connector+" "+name, func(t *testing.T) {
			var request []byte
			// The gateway blocks only a request that names the protected
			// target: a review without it would be allowed.
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				request, _ = io.ReadAll(r.Body)
				w.Header().Set("Content-Type", "application/json")
				if !strings.Contains(string(request), "/home/user/.ssh/authorized_keys") {
					_, _ = io.WriteString(w, `{"action":"allow","raw_action":"allow","mode":"action","hook_output":{"decision":"allow"}}`)
					return
				}
				_, _ = io.WriteString(w, `{"action":"block","mode":"action","hook_output":{"decision":"deny","reason":"protected target"}}`)
			}))
			t.Cleanup(server.Close)
			home := t.TempDir()
			installNativeGatewayForHookTest(t, home)
			dataDir := filepath.Join(home, ".defenseclaw")
			token := filepath.Join(dataDir, "hooks", ".hook-"+plugin.connector+".token")
			if err := os.MkdirAll(filepath.Dir(token), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(token, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			body := renderPluginAssetForTest(t, plugin.asset, templateData{
				APIAddr: strings.TrimPrefix(server.URL, "http://"), TokenFileJS: javaScriptStringContent(token),
				FailMode: "closed", OutageFailMode: "open",
			})
			path := filepath.Join(home, plugin.name)
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			harness := strings.ReplaceAll(plugin.harness, `command: "echo marker"`, plugin.input)
			cmd := exec.Command(nodeForTest(t), "--input-type=module", "-e", harness, path)
			cmd.Env = append(sanitizedTestEnv(), "HOME="+home)
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("node: %v\n%s", err, out)
			}
			var result struct {
				Verdict string `json:"verdict"`
			}
			if err := json.Unmarshal([]byte(strings.TrimSpace(string(out))), &result); err != nil {
				t.Fatal(err)
			}
			if plugin.local {
				if !strings.HasPrefix(result.Verdict, "block:") || strings.Contains(string(request), `"bounded_prefix_review":true`) {
					t.Fatalf("local block=%q request=%.300q", result.Verdict, request)
				}
				return
			}
			if !strings.HasPrefix(result.Verdict, "block:") || !strings.Contains(string(request), `"bounded_prefix_review":true`) || !strings.Contains(string(request), "/home/user/.ssh/authorized_keys") {
				t.Fatalf("gateway block=%q request=%.300q", result.Verdict, request)
			}
		})
	}
}

// oss-outage-open for the in-agent plugins: a per-user OpenCode or Amp plugin
// in the default or permissive tier lets a tool call run with one warning and
// a hook-failures.jsonl row only when its native helper finds no gateway; the
// strict tier blocks it. An answer the gateway gave (malformed, an error
// status) and the install window block in every tier. The real native helper
// (defenseclaw-gateway hook-post) carries every call.
func TestPerUserPluginOutageOpenOnlyForAnOutage(t *testing.T) {
	nodeForTest(t)
	type scenario struct {
		name    string
		handler http.HandlerFunc
		lock    bool
		opens   bool
	}
	scenarios := []scenario{
		{name: "gateway up", handler: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"action":"allow","raw_action":"allow","mode":"observe","hook_output":{"decision":"allow"}}`))
		}, opens: true},
		{name: "gateway down", opens: true},
		{name: "gateway down, install in progress", lock: true},
		{name: "malformed answer", handler: func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"action":"allow" garbage`))
		}},
		{name: "gateway error status", handler: func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		}},
	}
	for _, plugin := range []struct{ asset, name, connector, harness string }{
		{"opencode-plugin.js", "defenseclaw.mjs", "opencode", openCodeOutageHarness},
		{"amp-plugin.ts", "defenseclaw.mts", "amp", ampOutageHarness},
	} {
		for _, tier := range []struct{ name, mode string }{{"default or permissive", "open"}, {"strict", "closed"}} {
			for _, sc := range scenarios {
				t.Run(plugin.connector+"/"+tier.name+"/"+sc.name, func(t *testing.T) {
					t.Parallel()
					home := t.TempDir()
					installNativeGatewayForHookTest(t, home)
					dataDir := filepath.Join(home, ".defenseclaw")
					token := filepath.Join(dataDir, "hooks", ".hook-"+plugin.connector+".token")
					if err := os.MkdirAll(filepath.Dir(token), 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(token, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
						t.Fatal(err)
					}
					var addr string
					if sc.handler != nil {
						server := httptest.NewServer(sc.handler)
						defer server.Close()
						addr = strings.TrimPrefix(server.URL, "http://")
					} else {
						addr = freeLoopbackAddrForOutageTest(t)
					}
					if sc.lock {
						if err := os.WriteFile(filepath.Join(dataDir, ".install.lock"), nil, 0o600); err != nil {
							t.Fatal(err)
						}
					}
					body := renderPluginAssetForTest(t, plugin.asset, templateData{APIAddr: addr, TokenFileJS: javaScriptStringContent(token),
						FailMode: "closed", OutageFailMode: tier.mode})
					path := filepath.Join(home, plugin.name)
					if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
						t.Fatal(err)
					}
					cmd := exec.Command(nodeForTest(t), "--input-type=module", "-e", plugin.harness, path)
					cmd.Env = append(sanitizedTestEnv(), "HOME="+home)
					out, err := cmd.Output()
					if err != nil {
						t.Fatalf("node: %v\n%s", err, out)
					}
					var result struct {
						Verdict string   `json:"verdict"`
						Notices []string `json:"notices"`
					}
					if err := json.Unmarshal([]byte(strings.TrimSpace(string(out))), &result); err != nil {
						t.Fatalf("harness output %q: %v", out, err)
					}
					wantRun := sc.name == "gateway up" || (sc.opens && tier.mode == "open")
					if (result.Verdict == "allow") != wantRun {
						t.Fatalf("verdict %q, want run=%v", result.Verdict, wantRun)
					}
					if sc.name != "gateway down" {
						return
					}
					rows := hookFailureRecords(t, dataDir)
					if tier.mode == "closed" {
						if len(rows) != 0 || !strings.Contains(result.Verdict, "defenseclaw-gateway start") {
							t.Fatalf("strict tier: verdict %q rows %+v, want a block that names the start step and no fail-open row", result.Verdict, rows)
						}
						return
					}
					if len(rows) != 1 || rows[0]["connector"] != plugin.connector || rows[0]["fail_mode"] != "open" || rows[0]["category"] != "transport" {
						t.Fatalf("hook-failures rows = %+v, want one open transport row", rows)
					}
					notice := strings.Join(result.Notices, "\n")
					for _, want := range []string{"defenseclaw-gateway start", "defenseclaw doctor", "fail mode open for an outage"} {
						if !strings.Contains(notice, want) {
							t.Fatalf("notices %q do not name %q", result.Notices, want)
						}
					}
				})
			}
		}
	}
}

func TestPerUserPluginOversizedPayloadUsesInstalledTier(t *testing.T) {
	nodeForTest(t)
	for _, plugin := range []struct{ asset, name, connector, harness string }{
		{"opencode-plugin.js", "defenseclaw.mjs", "opencode", openCodeOutageHarness},
		{"amp-plugin.ts", "defenseclaw.mts", "amp", ampOutageHarness},
	} {
		for _, tier := range []struct{ name, mode string }{{"balanced", "open"}, {"strict", "closed"}} {
			t.Run(plugin.connector+"/"+tier.name, func(t *testing.T) {
				home := t.TempDir()
				installNativeGatewayForHookTest(t, home)
				dataDir := filepath.Join(home, ".defenseclaw")
				token := filepath.Join(dataDir, "hooks", ".hook-"+plugin.connector+".token")
				if err := os.MkdirAll(filepath.Dir(token), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(token, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				body := renderPluginAssetForTest(t, plugin.asset, templateData{
					APIAddr: "127.0.0.1:1", TokenFileJS: javaScriptStringContent(token),
					FailMode: "closed", OutageFailMode: tier.mode,
				})
				path := filepath.Join(home, plugin.name)
				if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
				harness := strings.ReplaceAll(plugin.harness, `command: "echo marker"`, `description: "x".repeat(1100000), command: "echo marker"`)
				cmd := exec.Command(nodeForTest(t), "--input-type=module", "-e", harness, path)
				cmd.Env = append(sanitizedTestEnv(), "HOME="+home)
				out, err := cmd.Output()
				if err != nil {
					t.Fatalf("node: %v\n%s", err, out)
				}
				var result struct {
					Verdict string   `json:"verdict"`
					Notices []string `json:"notices"`
				}
				if err := json.Unmarshal([]byte(strings.TrimSpace(string(out))), &result); err != nil {
					t.Fatalf("harness output %q: %v", out, err)
				}
				rows := hookFailureRecords(t, dataDir)
				if tier.mode == "open" {
					if result.Verdict != "allow" || len(rows) != 1 || rows[0]["outcome"] != "fail_open" ||
						!strings.Contains(strings.Join(result.Notices, "\n"), "fail mode open for an outage") {
						t.Fatalf("balanced verdict=%q notices=%q rows=%+v", result.Verdict, result.Notices, rows)
					}
				} else if !strings.HasPrefix(result.Verdict, "block:") || len(rows) != 0 {
					t.Fatalf("strict verdict=%q rows=%+v", result.Verdict, rows)
				}
			})
		}
	}
}
