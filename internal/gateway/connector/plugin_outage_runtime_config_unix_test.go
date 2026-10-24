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
	"sync"
	"testing"
)

// writePluginOutageTokenForTest writes the plugin's scoped token in
// dataDir/hooks and returns its path.
func writePluginOutageTokenForTest(t *testing.T, dataDir, connector string) string {
	t.Helper()
	token := filepath.Join(dataDir, "hooks", ".hook-"+connector+".token")
	if err := os.MkdirAll(filepath.Dir(token), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(token, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return token
}

// oss-outage-open review (loop round 3): an OpenCode or Amp plugin asks the
// config of its own data directory (the one above its token's hooks folder)
// for the outage mode. The agent's DEFENSECLAW_CONFIG or DEFENSECLAW_HOME,
// which name another default-tier config, neither reopen an outage the
// runtime's strict config closes nor close one its default config opens.
func TestPerUserPluginOutageReadsOnlyItsRuntimesConfig(t *testing.T) {
	nodeForTest(t)
	for _, plugin := range []struct{ asset, name, connector, harness string }{
		{"opencode-plugin.js", "defenseclaw.mjs", "opencode", openCodeOutageHarness},
		{"amp-plugin.ts", "defenseclaw.mts", "amp", ampOutageHarness},
	} {
		for _, tc := range []struct {
			name, runtime, agent string
			env                  func(other string) []string
			opens                bool
		}{
			{name: "DEFENSECLAW_CONFIG names a default config elsewhere", runtime: outageStrictTierConfig, agent: outageDefaultTierConfig,
				env: func(other string) []string {
					return []string{"DEFENSECLAW_CONFIG=" + filepath.Join(other, "config.yaml")}
				}},
			{name: "DEFENSECLAW_HOME names a default home elsewhere", runtime: outageStrictTierConfig, agent: outageDefaultTierConfig,
				env: func(other string) []string { return []string{"DEFENSECLAW_HOME=" + other} }},
			{name: "the environment names a strict config elsewhere", runtime: outageDefaultTierConfig, agent: outageStrictTierConfig,
				env: func(other string) []string {
					return []string{"DEFENSECLAW_HOME=" + other, "DEFENSECLAW_CONFIG=" + filepath.Join(other, "config.yaml")}
				}, opens: true},
		} {
			t.Run(plugin.connector+"/"+tc.name, func(t *testing.T) {
				t.Parallel()
				home := t.TempDir()
				other := t.TempDir()
				installNativeGatewayForHookTest(t, home)
				dataDir := filepath.Join(home, ".defenseclaw")
				token := writePluginOutageTokenForTest(t, dataDir, plugin.connector)
				writeOutageTierConfig(t, dataDir, tc.runtime)
				writeOutageTierConfig(t, other, tc.agent)
				// Rendered in the default tier: the plugin bakes open.
				body := renderPluginAssetForTest(t, plugin.asset, templateData{APIAddr: freeLoopbackAddrForOutageTest(t),
					TokenFileJS: javaScriptStringContent(token), FailMode: "closed", OutageFailMode: "open"})
				path := filepath.Join(home, plugin.name)
				if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command(nodeForTest(t), "--input-type=module", "-e", plugin.harness, path)
				cmd.Env = append(append(sanitizedTestEnv(), "HOME="+home, "DEFENSECLAW_GATEWAY_AUTOSTART=0"), tc.env(other)...)
				out, err := cmd.Output()
				if err != nil {
					t.Fatalf("node: %v\n%s", err, out)
				}
				var result struct {
					Verdict string `json:"verdict"`
				}
				if err := json.Unmarshal([]byte(strings.TrimSpace(string(out))), &result); err != nil {
					t.Fatalf("harness output %q: %v", out, err)
				}
				if (result.Verdict == "allow") != tc.opens {
					t.Fatalf("verdict %q, want run=%v", result.Verdict, tc.opens)
				}
			})
		}
	}
}

const ampToolResultOutageHarness = `
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
const callNotices = notices.length;
const result = await handlers.get("tool.result")({ thread: { id: "S" }, toolUseID: "C", tool: "Bash", input: { command: "echo marker" }, output: "marker", status: "done" }, ctx);
console.log(JSON.stringify({ call: call.action, kept: result === undefined, callNotices, notices }));
`

// oss-outage-open review (loop round 3): the gateway answers Amp's tool.call
// and stops before its tool.result. In the default or permissive tier the
// result is kept with the same one outage warning a call gets and one
// hook-failures.jsonl row; the strict tier withholds it. Before, the
// tool.result allow dropped the warning, so the user was not told the result
// reached the model unchecked.
func TestAmpToolResultAfterTheGatewayStopsCarriesTheOutageWarning(t *testing.T) {
	nodeForTest(t)
	for _, tier := range []struct{ name, mode, config string }{
		{"default or permissive", "open", outageDefaultTierConfig},
		{"strict", "closed", outageStrictTierConfig},
	} {
		t.Run(tier.name, func(t *testing.T) {
			t.Parallel()
			home := t.TempDir()
			installNativeGatewayForHookTest(t, home)
			dataDir := filepath.Join(home, ".defenseclaw")
			token := writePluginOutageTokenForTest(t, dataDir, "amp")
			writeOutageTierConfig(t, dataDir, tier.config)
			var stop sync.Once
			var server *httptest.Server
			server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				if strings.Contains(string(body), `"tool.call"`) {
					// The gateway answers this call and is gone for the
					// next one: no listener takes the tool.result.
					stop.Do(func() { _ = server.Listener.Close() })
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"action":"allow","raw_action":"allow","mode":"observe","hook_output":{"decision":"allow"}}`))
			}))
			server.Start()
			defer server.Close()
			body := renderPluginAssetForTest(t, "amp-plugin.ts", templateData{APIAddr: strings.TrimPrefix(server.URL, "http://"),
				TokenFileJS: javaScriptStringContent(token), FailMode: "closed", OutageFailMode: tier.mode})
			path := filepath.Join(home, "defenseclaw.mts")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(nodeForTest(t), "--input-type=module", "-e", ampToolResultOutageHarness, path)
			cmd.Env = append(sanitizedTestEnv(), "HOME="+home, "DEFENSECLAW_GATEWAY_AUTOSTART=0")
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("node: %v\n%s", err, out)
			}
			var result struct {
				Call        string   `json:"call"`
				Kept        bool     `json:"kept"`
				CallNotices int      `json:"callNotices"`
				Notices     []string `json:"notices"`
			}
			if err := json.Unmarshal([]byte(strings.TrimSpace(string(out))), &result); err != nil {
				t.Fatalf("harness output %q: %v", out, err)
			}
			if result.Call != "allow" || result.CallNotices != 0 {
				t.Fatalf("the answered tool.call = %q with %d notices, want allow and none", result.Call, result.CallNotices)
			}
			rows := hookFailureRecords(t, dataDir)
			if tier.mode == "closed" {
				if result.Kept || len(rows) != 0 {
					t.Fatalf("strict tier: kept=%v rows=%+v, want the result withheld and no fail-open row", result.Kept, rows)
				}
				return
			}
			if !result.Kept {
				t.Fatal("default tier: the tool result was withheld during an outage")
			}
			if len(rows) != 1 || rows[0]["fail_mode"] != "open" || rows[0]["category"] != "transport" {
				t.Fatalf("hook-failures rows = %+v, want one open transport row", rows)
			}
			notice := strings.Join(result.Notices, "\n")
			if len(result.Notices) != 1 {
				t.Fatalf("notices %q, want the one outage warning", result.Notices)
			}
			for _, want := range []string{"defenseclaw-gateway start", "defenseclaw doctor", "fail mode open for an outage"} {
				if !strings.Contains(notice, want) {
					t.Fatalf("notices %q do not name %q", result.Notices, want)
				}
			}
		})
	}
}
