// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// The installer holds this lock while it stops and replaces the account's
// gateway. A plugin rendered for fail mode open must still stop actionable
// calls until that transaction has completed, for a refused connection, a
// gateway error response and an answer without a verdict. A valid allow the
// gateway gave keeps its answer in the window too (owner decision
// 2026-10-24, GAP-1372: the plugin's deny of it was a benign false block).
// Outside the window a per-user plugin is closed whatever mode it was asked
// for (sa-port-peer): failures block and a valid allow runs.
//
// The carry reads the outage mode at call time (fix/r104-oss-outage-open):
// the plugin asks the helper its .gateway-helper record names
// (hook-outage-mode --install-window), and the window is open only for the
// default and permissive tiers; the strict tier and any doubt close it
// (OWNER DECISION 2026-10-24 20:33). installWindowTierForTest gives the
// plugin the default tier's answer. The lock is stale only when its
// installer is proven gone; no clock is read.
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
			openWindow := installWindowTierForTest(t, filepath.Dir(token))
			data := templateData{APIAddr: "127.0.0.1:1", TokenFileJS: javaScriptStringContent(token), FailMode: "open",
				WindowsPowerShellJS: javaScriptStringContent(windowsSystemPowerShellExe())}
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
			during := func(phase string) {
				t.Helper()
				blocked := session.request(phase, "call")
				if failure == "valid-allow" && openWindow {
					if blocked != "allow" {
						t.Fatalf("valid allow %s = %q; want the gateway's allow", phase, blocked)
					}
				} else if !strings.HasPrefix(blocked, "block:") ||
					!strings.Contains(blocked, "being installed or upgraded") ||
					!strings.Contains(blocked, "run the installer again") ||
					strings.Contains(blocked, "defenseclaw-gateway start") {
					t.Fatalf("%s %s = %q; want a block naming the install", failure, phase, blocked)
				}
			}
			during("during install")
			afterLog, afterErr := os.ReadFile(filepath.Join(dataDir, "logs", "hook-failures.jsonl"))
			if afterErr != nil && !os.IsNotExist(afterErr) {
				t.Fatal(afterErr)
			}
			if string(afterLog) != string(beforeLog) {
				t.Fatalf("%s logged a blocked install call as fail-open", failure)
			}
			then := time.Now().Add(-11 * time.Minute)
			if err := os.Chtimes(lock, then, then); err != nil {
				t.Fatal(err)
			}
			// No clock: an old lock that names no installer pid yet still holds.
			during("old install lock without an installer pid")
			if err := os.Chtimes(lock, time.Now(), time.Now()); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(lock, "pid"), []byte("99999999\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			outside("dead install owner")
			if err := os.Remove(filepath.Join(lock, "pid")); err != nil {
				t.Fatal(err)
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
  if (process.argv[2] === "invalid-verdict") return { ok: true, text: async () => JSON.stringify({ action: "unknown" }) };
  if (process.argv[2] === "valid-allow") return { ok: true, text: async () => JSON.stringify({ action: "allow", hook_output: { decision: "allow" } }) };
  return { ok: false, status: 503 };
};
`

const openCodeInstallWindowHarness = `
import { pathToFileURL } from "node:url";
import { createInterface } from "node:readline";
` + pluginInstallFailureFetch + `
const href = pathToFileURL(process.argv[1]).href;
const plugin = await fixtureBridge(await import(href), { directory: "", client: { tui: { showToast: async () => true } } });
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
	// Amp's two actionable boundaries must both block a failure during the
	// same window.
	for _, failure := range []string{"transport", "http", "invalid-verdict", "valid-allow"} {
		t.Run(failure, func(t *testing.T) {
			dataDir := testenv.PrivateTempDir(t)
			token := filepath.Join(dataDir, "hooks", ".hook-amp.token")
			if err := os.MkdirAll(filepath.Dir(token), 0o700); err != nil {
				t.Fatal(err)
			}
			openWindow := installWindowTierForTest(t, filepath.Dir(token))
			plugin := writeRenderedPlugin(t, "amp-plugin.ts", "defenseclaw.mts", templateData{
				APIAddr: "127.0.0.1:1", TokenFileJS: javaScriptStringContent(token), FailMode: "open",
				WindowsPowerShellJS: javaScriptStringContent(windowsSystemPowerShellExe()),
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
			// GAP-1372: a valid allow the gateway gave keeps its answer in the
			// default tier's window; every failure blocks both boundaries.
			check("during install", failure != "valid-allow" || !openWindow)
			if err := os.Remove(lock); err != nil {
				t.Fatal(err)
			}
			check("after install", false)
			session.close()
		})
	}
}

// installWindowTierForTest writes the per-user helper and its .gateway-helper
// record beside a rendered plugin's token: it answers hook-outage-mode
// --install-window with the default tier's "open" and every other outage
// mode with "closed". On native Windows the record must name an executable
// <home>\.local\bin\defenseclaw-gateway.exe, so the helper there is a small
// program built from installWindowHelperSource (GAP-1836: the Windows rows
// assert the default tier's allow in the window, GAP-1372, not a doubt block).
// DEFENSECLAW_HOME names an empty folder, so no lock of this account counts.
func installWindowTierForTest(t *testing.T, hookDir string) bool {
	t.Helper()
	t.Setenv("DEFENSECLAW_HOME", testenv.PrivateTempDir(t))
	bin := filepath.Join(testenv.PrivateTempDir(t), ".local", "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	name := "defenseclaw-gateway"
	if runtime.GOOS == "windows" {
		name += ".exe"
		body, err := os.ReadFile(installWindowHelperExeForTest(t))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(bin, name), body, 0o700); err != nil {
			t.Fatal(err)
		}
	} else {
		helper := "#!/bin/sh\nif [ \"$1\" = hook-outage-mode ]; then\n" +
			"  case \" $* \" in *\" --install-window \"*) printf 'open\\n' ;; *) printf 'closed\\n' ;; esac\n  exit 0\nfi\nexit 1\n"
		if err := os.WriteFile(filepath.Join(bin, name), []byte(helper), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	recordGatewayHelperForTest(t, hookDir, filepath.Join(bin, name))
	return true
}

// installWindowHelperSource is the Windows helper of installWindowTierForTest:
// the shell helper's answers as a program.
const installWindowHelperSource = `package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "hook-outage-mode" {
		os.Exit(1)
	}
	for _, arg := range os.Args[2:] {
		if arg == "--install-window" {
			fmt.Println("open")
			return
		}
	}
	fmt.Println("closed")
}
`

var installWindowHelperExe struct {
	once sync.Once
	path string
	err  error
}

// installWindowHelperExeForTest builds installWindowHelperSource once per test
// binary, or takes the prebuilt DC_TEST_INSTALL_WINDOW_HELPER (an absolute
// path; a native Windows run from a cross-built test binary has no go).
func installWindowHelperExeForTest(t *testing.T) string {
	t.Helper()
	installWindowHelperExe.once.Do(func() {
		if prebuilt := os.Getenv("DC_TEST_INSTALL_WINDOW_HELPER"); filepath.IsAbs(prebuilt) {
			installWindowHelperExe.path = prebuilt
			return
		}
		dir, err := os.MkdirTemp("", "defenseclaw-install-window-helper-")
		if err != nil {
			installWindowHelperExe.err = err
			return
		}
		for name, body := range map[string]string{"go.mod": "module installwindowhelper\n\ngo 1.22\n", "main.go": installWindowHelperSource} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
				installWindowHelperExe.err = err
				return
			}
		}
		installWindowHelperExe.path = filepath.Join(dir, "defenseclaw-gateway.exe")
		cmd := exec.Command("go", "build", "-o", installWindowHelperExe.path, ".")
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=")
		if output, err := cmd.CombinedOutput(); err != nil {
			installWindowHelperExe.err = fmt.Errorf("build the install-window helper: %w: %s", err, output)
		}
	})
	if installWindowHelperExe.err != nil {
		t.Fatal(installWindowHelperExe.err)
	}
	return installWindowHelperExe.path
}
