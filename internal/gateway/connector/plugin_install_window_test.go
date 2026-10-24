// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// The installer holds this lock while it stops and replaces the account's
// gateway. A plugin rendered for fail mode open must still stop actionable
// calls until that transaction has completed, for both a refused connection
// and a gateway error response. Outside the window a per-user plugin is
// closed whatever mode it was asked for (sa-port-peer): failures block and a
// valid allow runs.
func pluginInstallWindowCases(t *testing.T, asset, extension, harness string) {
	t.Helper()
	nodeForTest(t)
	for _, failure := range []string{"transport", "http", "invalid-verdict", "valid-allow"} {
		t.Run(failure, func(t *testing.T) {
			dataDir := testenv.PrivateTempDir(t)
			token := filepath.Join(dataDir, "hooks", ".hook-"+strings.TrimSuffix(asset, "-plugin"+extension)+".token")
			if err := os.MkdirAll(filepath.Dir(token), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(token, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			data := templateData{APIAddr: "127.0.0.1:1", TokenFileJS: javaScriptStringContent(token), FailMode: "open"}
			plugin := writeRenderedPlugin(t, asset, "defenseclaw."+strings.TrimPrefix(extension, "."), data)
			// Load once before the upgrade starts. An agent keeps this module in
			// memory when the installer replaces the plugin file on disk.
			session := startNodeHarnessSession(t, harness, plugin, failure)
			outside := func(phase string) {
				t.Helper()
				got := session.request(phase, "call")
				if failure == "valid-allow" {
					if got != "allow" {
						t.Fatalf("%s %s = %q, want the gateway's allow", failure, phase, got)
					}
				} else if !strings.HasPrefix(got, "block:") || strings.Contains(got, "being installed or upgraded") {
					t.Fatalf("%s %s = %q, want the closed failure block", failure, phase, got)
				}
			}
			outside("before install")
			beforeLog, beforeErr := os.ReadFile(filepath.Join(dataDir, "logs", "hook-failures.jsonl"))
			if beforeErr != nil && !os.IsNotExist(beforeErr) {
				t.Fatal(beforeErr)
			}
			lock := filepath.Join(dataDir, ".install.lock")
			if err := os.Mkdir(lock, 0o700); err != nil {
				t.Fatal(err)
			}
			blocked := session.request("during install", "call")
			if !strings.HasPrefix(blocked, "block:") ||
				!strings.Contains(blocked, "being installed or upgraded") ||
				!strings.Contains(blocked, "run the installer again") ||
				strings.Contains(blocked, "defenseclaw-gateway start") {
				t.Fatalf("%s with install lock = %q; want a block naming the install", failure, blocked)
			}
			afterLog, afterErr := os.ReadFile(filepath.Join(dataDir, "logs", "hook-failures.jsonl"))
			if afterErr != nil && !os.IsNotExist(afterErr) {
				t.Fatal(afterErr)
			}
			if string(afterLog) != string(beforeLog) {
				t.Fatalf("%s logged a blocked install call as fail-open", failure)
			}
			if err := os.Remove(lock); err != nil {
				t.Fatal(err)
			}
			outside("after install")
			session.close()
		})
	}
}

const pluginInstallFailureFetch = `
globalThis.fetch = async () => {
  if (process.argv[2] === "transport") throw Object.assign(new Error("connect ECONNREFUSED"), { code: "ECONNREFUSED" });
  if (process.argv[2] === "invalid-verdict") return { ok: true, json: async () => ({ action: "unknown" }) };
  if (process.argv[2] === "valid-allow") return { ok: true, json: async () => ({ action: "allow", hook_output: { decision: "allow" } }) };
  return { ok: false, status: 503 };
};
`

const openCodeInstallWindowHarness = `
import { pathToFileURL } from "node:url";
import { createInterface } from "node:readline";
` + pluginInstallFailureFetch + `
const href = pathToFileURL(process.argv[1]).href;
const plugin = await (await import(href)).DefenseClaw({ directory: "", client: { tui: { showToast: async () => true } } });
await plugin.config({ plugin_origins: [{ spec: href }], mcp: {} });
console.log("harness-ready");
for await (const _ of createInterface({ input: process.stdin })) {
  try {
    await plugin["tool.execute.before"]({ tool: "bash", sessionID: "S", messageID: "M", callID: "C" }, { args: { command: "echo marker" } });
    console.log("allow");
  } catch (error) {
    console.log("block:" + String(error && error.message || error));
  }
}
`

func TestOpenCodePluginInstallWindowBlocksFailOpen(t *testing.T) {
	pluginInstallWindowCases(t, "opencode-plugin.js", ".js", openCodeInstallWindowHarness)
}

const ampInstallWindowHarness = `
import { pathToFileURL } from "node:url";
import { createInterface } from "node:readline";
` + pluginInstallFailureFetch + `
globalThis.Bun = { file: () => ({ slice: () => ({ text: async () => "a".repeat(64) + "\n" }) }) };
const handlers = new Map();
const amp = {
  system: { workspaceRoot: "", executor: { kind: "local" }, user: {} },
  helpers: { filePathFromURI: value => value, isPluginUINotAvailableError: () => false },
  activeThread: { current: { id: "S" } },
  ui: { notify: async () => {} },
  on: (event, handler) => { handlers.set(event, handler); return { unsubscribe() {} }; },
};
(await import(pathToFileURL(process.argv[1]).href)).default(amp);
const ctx = { thread: { agent: async () => ({ definition: { kind: "builtin-agent", mode: "medium" } }) }, ui: { confirm: async () => true } };
const event = { thread: { id: "S" }, toolUseID: "C", tool: "Bash", input: { command: "echo marker" } };
console.log("harness-ready");
for await (const _ of createInterface({ input: process.stdin })) {
  const call = await handlers.get("tool.call")(event, ctx);
  const result = await handlers.get("tool.result")({ ...event, output: "result", status: "success" }, ctx);
  console.log(JSON.stringify({ action: call.action, message: call.message || "", status: result?.status || "unchanged", error: result?.error || "" }));
}
`

func TestAmpPluginInstallWindowBlocksFailOpen(t *testing.T) {
	// Amp's two actionable boundaries must both block during the same window.
	for _, failure := range []string{"transport", "http", "invalid-verdict", "valid-allow"} {
		t.Run(failure, func(t *testing.T) {
			dataDir := testenv.PrivateTempDir(t)
			token := filepath.Join(dataDir, "hooks", ".hook-amp.token")
			if err := os.MkdirAll(filepath.Dir(token), 0o700); err != nil {
				t.Fatal(err)
			}
			plugin := writeRenderedPlugin(t, "amp-plugin.ts", "defenseclaw.mts", templateData{
				APIAddr: "127.0.0.1:1", TokenFileJS: javaScriptStringContent(token), FailMode: "open",
			})
			// Amp also keeps its handlers loaded for the whole agent process.
			session := startNodeHarnessSession(t, ampInstallWindowHarness, plugin, failure)
			lock := filepath.Join(dataDir, ".install.lock")
			check := func(phase string, wantBlocked bool) {
				t.Helper()
				lines := session.request(phase, "call")
				var verdict struct{ Action, Message, Status, Error string }
				if err := json.Unmarshal([]byte(lines), &verdict); err != nil {
					t.Fatal(err)
				}
				if wantBlocked {
					if verdict.Action != "reject-and-continue" || verdict.Status != "error" ||
						!strings.Contains(verdict.Message, "being installed or upgraded") ||
						!strings.Contains(verdict.Error, "being installed or upgraded") ||
						!strings.Contains(verdict.Message, "run the installer again") ||
						strings.Contains(verdict.Message, "defenseclaw-gateway start") {
						t.Fatalf("Amp with install lock = %+v; want both boundaries blocked", verdict)
					}
				} else if failure == "valid-allow" {
					if verdict.Action != "allow" || verdict.Status != "unchanged" {
						t.Fatalf("Amp without install lock = %+v; want the gateway's allow", verdict)
					}
				} else if verdict.Action != "reject-and-continue" || strings.Contains(verdict.Message, "being installed or upgraded") {
					// A per-user plugin renders closed whatever mode it was asked
					// for (sa-port-peer): the failure blocks without the lock too.
					t.Fatalf("Amp without install lock = %+v; want the closed failure block", verdict)
				}
			}
			check("before install", false)
			if err := os.Mkdir(lock, 0o700); err != nil {
				t.Fatal(err)
			}
			check("during install", true)
			if err := os.Remove(lock); err != nil {
				t.Fatal(err)
			}
			check("after install", false)
			session.close()
		})
	}
}
