// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"encoding/json"
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
		for _, tier := range []struct{ name, mode, config string }{
			{"default or permissive", "open", outageDefaultTierConfig},
			{"strict", "closed", outageStrictTierConfig},
		} {
			for _, sc := range scenarios {
				t.Run(plugin.connector+"/"+tier.name+"/"+sc.name, func(t *testing.T) {
					t.Parallel()
					home := t.TempDir()
					installNativeGatewayForHookTest(t, home)
					dataDir := filepath.Join(home, ".defenseclaw")
					writeOutageTierConfig(t, dataDir, tier.config)
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
						FailMode: "closed"})
					path := filepath.Join(home, plugin.name)
					if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
						t.Fatal(err)
					}
					cmd := exec.Command(nodeForTest(t), "--input-type=module", "-e", plugin.harness, path)
					cmd.Env = append(sanitizedTestEnv(), "HOME="+home, "DEFENSECLAW_GATEWAY_AUTOSTART=0")
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

// The current runtime config decides a plugin's outage, even when the last
// render recorded a different tier. A strict pack or a config this release
// cannot read closes it; the default pack opens it with one warning and one
// audit row.
func TestPerUserPluginOutageFollowsTheConfigNow(t *testing.T) {
	nodeForTest(t)
	for _, plugin := range []struct{ asset, name, connector, harness string }{
		{"opencode-plugin.js", "defenseclaw.mjs", "opencode", openCodeOutageHarness},
		{"amp-plugin.ts", "defenseclaw.mts", "amp", ampOutageHarness},
	} {
		for _, tc := range []struct {
			name, config string
			opens        bool
		}{
			{"default pack after a strict render", outageDefaultTierConfig, true},
			{"strict pack", outageStrictTierConfig, false},
			{"strict pack for this connector", outageDefaultTierConfig + "  connectors:\n    " + plugin.connector + ":\n      rule_pack: strict\n", false},
			{"no config", "", false},
			{"config this release cannot read", "config_version: 9\nguardrail: [\n", false},
		} {
			t.Run(plugin.connector+"/"+tc.name, func(t *testing.T) {
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
				writeOutageTierConfig(t, dataDir, tc.config)
				// A strict render can remain installed when the gateway is stopped.
				body := renderPluginAssetForTest(t, plugin.asset, templateData{APIAddr: freeLoopbackAddrForOutageTest(t),
					TokenFileJS: javaScriptStringContent(token), FailMode: "closed"})
				path := filepath.Join(home, plugin.name)
				if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command(nodeForTest(t), "--input-type=module", "-e", plugin.harness, path)
				cmd.Env = append(sanitizedTestEnv(), "HOME="+home, "DEFENSECLAW_GATEWAY_AUTOSTART=0")
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
				if (result.Verdict == "allow") != tc.opens {
					t.Fatalf("verdict %q, want run=%v", result.Verdict, tc.opens)
				}
				rows := hookFailureRecords(t, dataDir)
				if tc.opens {
					if len(rows) != 1 || rows[0]["fail_mode"] != "open" || rows[0]["category"] != "transport" || len(result.Notices) != 1 ||
						!strings.Contains(result.Notices[0], "fail mode open for an outage") {
						t.Fatalf("open outage rows=%+v notices=%q, want one audit row and one warning", rows, result.Notices)
					}
				} else if len(rows) != 0 {
					t.Fatalf("a closed outage wrote fail-open rows %+v", rows)
				}
			})
		}
	}
}
