// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// oss-outage-open round h loop 2 (P2, stale install lock): an installer
// killed after it made .install.lock left the lock, and Amp and OpenCode
// then blocked every tool call a healthy gateway answered, for good. Both
// plugins share one rule (installLockState, hookexec installLockStale): a
// lock whose installer is proven gone is no lock, so a reachable gateway's
// answer runs and a failure follows the plugin's own rule; a live or
// uncertain install (here the strict-tier answer of a helper that cannot
// tell the tier) holds back the answer and blocks a failure as an install.
// Nothing under any lock logs a fail-open (round i).
func TestPerUserPluginsForwardAHealthyAnswerPastAStaleInstallLock(t *testing.T) {
	dead := startedAndExitedPid(t)
	live := strconv.Itoa(os.Getpid())
	makeLock := func(pid string, age time.Duration) func(*testing.T, string) {
		return func(t *testing.T, lock string) {
			t.Helper()
			if err := os.Mkdir(lock, 0o700); err != nil {
				t.Fatal(err)
			}
			if pid != "" {
				if err := os.WriteFile(filepath.Join(lock, "pid"), []byte(pid), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if age > 0 {
				then := time.Now().Add(-age)
				if err := os.Chtimes(lock, then, then); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	withRecord := func(record string, dir bool) func(*testing.T, string) {
		return func(t *testing.T, lock string) {
			t.Helper()
			makeLock(dead+"\n", 0)(t, lock)
			path := filepath.Join(filepath.Dir(lock), record)
			var err error
			if dir {
				err = os.Mkdir(path, 0o700)
			} else {
				err = os.WriteFile(path, []byte("{}"), 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	cases := []struct {
		name   string
		inHome bool
		lock   func(*testing.T, string)
		runs   bool
	}{
		{name: "installer exited", lock: makeLock(dead+"\n", 0), runs: true},
		{name: "installer exited, Windows line end", lock: makeLock(dead+"\r\n", 0), runs: true},
		{name: "installer running", lock: makeLock(live+"\n", 0)},
		{name: "no pid yet", lock: makeLock("", 0)},
		{name: "empty pid file", lock: makeLock(" ", 0)},
		{name: "no pid for eleven minutes", lock: makeLock("", 11*time.Minute), runs: true},
		{name: "pid not a number", lock: makeLock("abc", 0)},
		{name: "pid out of range, fresh", lock: makeLock("99999999999", 0)},
		{name: "running pid older than six hours", lock: makeLock(live, 7*time.Hour), runs: true},
		{name: "installer exited, interrupted install kept previous.new", lock: withRecord("previous.new", true)},
		{name: "installer exited, interrupted install kept .repair", lock: withRecord(".repair", true)},
		{name: "installer exited, interrupted install kept .rollback-hold", lock: withRecord(".rollback-hold", true)},
		{name: "installer exited, interrupted Windows install kept its record", lock: withRecord(".lifecycle-txn.json", false)},
		{name: "lock is a file", lock: func(t *testing.T, lock string) {
			if err := os.WriteFile(lock, []byte(dead), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "pid is a folder", lock: func(t *testing.T, lock string) {
			makeLock("", 0)(t, lock)
			if err := os.Mkdir(filepath.Join(lock, "pid"), 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "installer home: installer exited", inHome: true, lock: makeLock(dead+"\n", 0), runs: true},
		{name: "installer home: installer running", inHome: true, lock: makeLock(live+"\n", 0)},
	}
	for _, plugin := range []struct{ name, asset, file, harness string }{
		{"opencode", "opencode-plugin.js", "defenseclaw.js", openCodeInstallWindowHarness},
		{"amp", "amp-plugin.ts", "defenseclaw.mts", ampInstallWindowHarness},
	} {
		for _, tc := range cases {
			t.Run(plugin.name+"/"+tc.name, func(t *testing.T) {
				dataDir := testenv.PrivateTempDir(t)
				home := testenv.PrivateTempDir(t)
				// The plugin process inherits it: the installer's home.
				t.Setenv("DEFENSECLAW_HOME", home)
				token := filepath.Join(dataDir, "hooks", ".hook-"+plugin.name+".token")
				if err := os.MkdirAll(filepath.Dir(token), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(token, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				rendered := writeRenderedPlugin(t, plugin.asset, plugin.file, templateData{
					APIAddr: "127.0.0.1:1", TokenFileJS: javaScriptStringContent(token), FailMode: "open",
				})
				root := dataDir
				if tc.inHome {
					root = home
				}
				tc.lock(t, filepath.Join(root, ".install.lock"))
				for _, failure := range []string{"valid-allow", "transport", "invalid-verdict"} {
					session := startNodeHarnessSession(t, plugin.harness, rendered, failure)
					got := session.request(tc.name+" "+failure, "call")
					session.close()
					ran, installBlock := pluginStaleLockVerdict(t, plugin.name, got)
					if failure != "valid-allow" {
						if ran || installBlock == tc.runs {
							t.Fatalf("%s under the lock = %q; a failure must stay blocked, as an install only under a held lock", failure, got)
						}
						continue
					}
					if ran != tc.runs {
						t.Fatalf("healthy allow = %q; want it to run: %v", got, tc.runs)
					}
					if !tc.runs && !installBlock {
						t.Fatalf("healthy allow = %q; want the install block", got)
					}
				}
				if body, err := os.ReadFile(filepath.Join(dataDir, "logs", "hook-failures.jsonl")); err == nil && strings.Contains(string(body), "fail_open") {
					t.Fatalf("a call under the lock was logged as fail-open: %s", body)
				}
			})
		}
	}
}

// startedAndExitedPid is the pid of a process that has exited.
func startedAndExitedPid(t *testing.T) string {
	t.Helper()
	exited := exec.Command(nodeForTest(t), "-e", "")
	if err := exited.Run(); err != nil {
		t.Fatal(err)
	}
	return strconv.Itoa(exited.ProcessState.Pid())
}

func pluginStaleLockVerdict(t *testing.T, plugin, got string) (ran, installBlock bool) {
	t.Helper()
	if plugin == "opencode" {
		return got == "allow", strings.HasPrefix(got, "block:") && strings.Contains(got, "being installed or upgraded")
	}
	var verdict struct{ Action, Message, Status, Error string }
	if err := json.Unmarshal([]byte(got), &verdict); err != nil {
		t.Fatalf("amp harness answer %q: %v", got, err)
	}
	return verdict.Action == "allow" && verdict.Status == "unchanged",
		verdict.Action == "reject-and-continue" && strings.Contains(verdict.Message, "being installed or upgraded")
}
