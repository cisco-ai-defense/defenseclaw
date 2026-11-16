// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

const openCodeInstallTierHarness = `
import { pathToFileURL } from "node:url";
import { createInterface } from "node:readline";
` + pluginInstallFailureFetch + `
const notices = [];
const href = pathToFileURL(process.argv[1]).href;
console.warn = (message) => notices.push(String(message));
const plugin = await fixtureBridge(await import(href), { directory: "/work/repo" });
await plugin.config({ plugin_origins: [{ spec: href }], mcp: {} });
console.log("harness-ready");
let call = 0;
for await (const _ of createInterface({ input: process.stdin })) {
  let verdict = "allow";
  try {
    call++;
    await plugin["tool.execute.before"]({ tool: "bash", sessionID: "S" + call, messageID: "M", callID: "C" + call }, { args: { command: "echo marker" } });
  } catch (error) {
    verdict = "block:" + String(error && error.message || error);
  }
  console.log(JSON.stringify({ verdict, notices: notices.splice(0) }));
}
`

const ampInstallTierHarness = `
import { pathToFileURL } from "node:url";
import { createInterface } from "node:readline";
` + pluginInstallFailureFetch + `
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
console.log("harness-ready");
let call = 0;
for await (const _ of createInterface({ input: process.stdin })) {
  call++;
  const ctx = { thread: { agent: async () => ({ definition: { kind: "builtin-agent", mode: "medium" } }) }, ui: { confirm: async () => true, notify: async (message) => { notices.push(message); } } };
  const event = { thread: { id: "S" + call }, toolUseID: "C" + call, tool: "Bash", input: { command: "echo marker" } };
  const result = await handlers.get("tool.call")(event, ctx);
  const verdict = result.action === "allow" ? "allow" : "block:" + String(result.message || "");
  console.log(JSON.stringify({ verdict, notices: notices.splice(0) }));
}
`

// oss-outage-open round i (OWNER DECISION 2026-10-24 20:33, install lock):
// while an installer of this account runs, the default and permissive tiers
// let a call the gateway answered run, with a warning; the strict tier (and
// any doubt) blocks it. Every failure stays blocked as an install. A stale
// lock is no lock: its first call warns once.
func TestPerUserPluginsLetAnAnsweredCallRunDuringAnInstallInTheDefaultTier(t *testing.T) {
	nodeForTest(t)
	exited := startedAndExitedPid(t)
	for _, plugin := range []struct{ name, asset, file, harness string }{
		{"opencode", "opencode-plugin.js", "defenseclaw.js", openCodeInstallTierHarness},
		{"amp", "amp-plugin.ts", "defenseclaw.mts", ampInstallTierHarness},
	} {
		for _, tc := range []struct {
			name, window, failure, pid string
			runs, installBlock         bool
			notice                     string
		}{
			{name: "default tier, healthy allow", window: "open", failure: "valid-allow", runs: true, notice: "being installed or upgraded"},
			{name: "default tier, transport failure", window: "open", failure: "transport", installBlock: true},
			{name: "default tier, gateway error", window: "open", failure: "http", installBlock: true},
			{name: "default tier, invalid verdict", window: "open", failure: "invalid-verdict", installBlock: true},
			{name: "strict tier, healthy allow", window: "closed", failure: "valid-allow", installBlock: true},
			{name: "helper cannot tell, healthy allow", window: "fail", failure: "valid-allow", installBlock: true},
			{name: "stale lock, healthy allow", window: "closed", failure: "valid-allow", pid: exited, runs: true, notice: "no longer running"},
			{name: "stale lock, transport failure", window: "open", failure: "transport", pid: exited},
		} {
			t.Run(plugin.name+"/"+tc.name, func(t *testing.T) {
				dataDir := testenv.PrivateTempDir(t)
				helperHome := testenv.PrivateTempDir(t)
				t.Setenv("DEFENSECLAW_HOME", testenv.PrivateTempDir(t))
				t.Setenv("DC_TEST_WINDOW", tc.window)
				bin := filepath.Join(helperHome, ".local", "bin")
				if err := os.MkdirAll(bin, 0o700); err != nil {
					t.Fatal(err)
				}
				helper := "#!/bin/sh\nif [ \"$1\" = hook-outage-mode ]; then\n" +
					"  case \" $* \" in *\" --install-window \"*) ;; *) printf 'closed\\n'; exit 0 ;; esac\n" +
					"  [ \"$DC_TEST_WINDOW\" = fail ] && exit 1\n  printf '%s\\n' \"$DC_TEST_WINDOW\"; exit 0\nfi\nexit 1\n"
				if err := os.WriteFile(filepath.Join(bin, "defenseclaw-gateway"), []byte(helper), 0o700); err != nil {
					t.Fatal(err)
				}
				token := filepath.Join(dataDir, "hooks", ".hook-"+plugin.name+".token")
				if err := os.MkdirAll(filepath.Dir(token), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(token, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(filepath.Dir(token), ".gateway-helper"), []byte(filepath.Join(bin, "defenseclaw-gateway")+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				rendered := writeRenderedPlugin(t, plugin.asset, plugin.file, templateData{
					APIAddr: "127.0.0.1:1", TokenFileJS: javaScriptStringContent(token), FailMode: "open",
				})
				lock := filepath.Join(dataDir, ".install.lock")
				if err := os.Mkdir(lock, 0o700); err != nil {
					t.Fatal(err)
				}
				pid := tc.pid
				if pid == "" {
					pid = strconv.Itoa(os.Getpid())
				}
				record := map[string]string{"pid": pid, "started": strconv.FormatInt(time.Now().Unix(), 10),
					"deadline": strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)}
				for name, value := range record {
					if err := os.WriteFile(filepath.Join(lock, name), []byte(value+"\n"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				session := startNodeHarnessSession(t, plugin.harness, rendered, tc.failure)
				var first, second struct {
					Verdict string
					Notices []string
				}
				for _, out := range []*struct {
					Verdict string
					Notices []string
				}{&first, &second} {
					if err := json.Unmarshal([]byte(session.request(tc.name, "call")), out); err != nil {
						t.Fatal(err)
					}
				}
				session.close()
				for i, got := range []struct {
					Verdict string
					Notices []string
				}{first, second} {
					ran := got.Verdict == "allow"
					install := strings.HasPrefix(got.Verdict, "block:") && strings.Contains(got.Verdict, "being installed or upgraded")
					if ran != tc.runs || install != tc.installBlock || (!tc.runs && !strings.HasPrefix(got.Verdict, "block:")) {
						t.Fatalf("call %d = %+v; want runs %v, install block %v", i+1, got, tc.runs, tc.installBlock)
					}
				}
				warned := strings.Contains(strings.Join(first.Notices, "\n"), tc.notice)
				if tc.notice != "" && !warned {
					t.Fatalf("first call notices = %q; want the warning %q", first.Notices, tc.notice)
				}
				if tc.pid != "" && strings.Contains(strings.Join(second.Notices, "\n"), "no longer running") {
					t.Fatalf("a stale lock warned again: %q", second.Notices)
				}
				if body, err := os.ReadFile(filepath.Join(dataDir, "logs", "hook-failures.jsonl")); err == nil && strings.Contains(string(body), "fail_open") {
					t.Fatalf("a call under the lock was logged as fail-open: %s", body)
				}
			})
		}
	}
}
