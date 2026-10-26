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
	var makeAgedLock func(pid string, age, pidAge time.Duration) func(*testing.T, string)
	makeLock := func(pid string, age time.Duration) func(*testing.T, string) {
		return makeAgedLock(pid, age, 0)
	}
	makeAgedLock = func(pid string, age, pidAge time.Duration) func(*testing.T, string) {
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
			if pidAge != 0 {
				then := time.Now().Add(-pidAge)
				if err := os.Chtimes(filepath.Join(lock, "pid"), then, then); err != nil {
					t.Fatal(err)
				}
			}
			if age != 0 {
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
	withIdentity := func(reused bool, step time.Duration) func(*testing.T, string) {
		return func(t *testing.T, lock string) {
			t.Helper()
			identity, other := installLockIdentityOf(t, os.Getpid())
			if reused {
				identity = other
			}
			makeAgedLock(live+"\n", 0, step)(t, lock)
			if err := os.WriteFile(filepath.Join(lock, "proc-start"), []byte(identity+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Round l loop 1 (P2): an installer that exited but is not reaped (a
	// zombie, or on Windows a process object a handle keeps) keeps its pid and
	// its start; its lock is no lock.
	ended, endedIdentity := endedInstallerPid(t)
	withEnded := func(record bool) func(*testing.T, string) {
		return func(t *testing.T, lock string) {
			t.Helper()
			makeLock(ended+"\n", 0)(t, lock)
			if record && endedIdentity != "" {
				if err := os.WriteFile(filepath.Join(lock, "proc-start"), []byte(endedIdentity+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	cases := []struct {
		name   string
		inHome bool
		lock   func(*testing.T, string)
		runs   bool
	}{
		{name: "installer exited, not reaped (zombie), with its proc-start record", lock: withEnded(true), runs: true},
		{name: "installer exited, not reaped (zombie), PID-only lock", lock: withEnded(false), runs: true},
		{name: "installer exited", lock: makeLock(dead+"\n", 0), runs: true},
		{name: "installer exited, Windows line end", lock: makeLock(dead+"\r\n", 0), runs: true},
		{name: "installer running", lock: makeLock(live+"\n", 0)},
		{name: "no pid yet", lock: makeLock("", 0)},
		{name: "empty pid file", lock: makeLock(" ", 0)},
		// Round k: no wait expires a lock without a pid (no clock is read).
		{name: "no pid for eleven minutes", lock: makeLock("", 11*time.Minute)},
		{name: "pid not a number", lock: makeLock("abc", 0)},
		{name: "pid out of range, fresh", lock: makeLock("99999999999", 0)},
		// Round j: a live installer keeps its lock however long it runs.
		{name: "running installer, lock made seven hours ago", lock: makeLock(live, 7*time.Hour)},
		// Round k: without a proc-start record no clock may tell a reused
		// pid from a live owner: a 1.0.2/1.0.3 PID-only lock holds while its
		// pid names a process, whenever the pid was written.
		{name: "1.0.2/1.0.3 PID-only lock, pid written a week before", lock: makeAgedLock(live, 7*24*time.Hour, 7*24*time.Hour)},
		{name: "1.0.2/1.0.3 PID-only lock, pid written a week ahead", lock: makeAgedLock(live, -7*24*time.Hour, -7*24*time.Hour)},
		// GAP-1024: an interrupted-install record does not hold the lock once
		// its installer is gone.
		{name: "installer exited, interrupted install kept previous.new", lock: withRecord("previous.new", true), runs: true},
		{name: "installer exited, interrupted install kept .repair", lock: withRecord(".repair", true), runs: true},
		{name: "installer exited, interrupted install kept .rollback-hold", lock: withRecord(".rollback-hold", true), runs: true},
		{name: "installer exited, interrupted Windows install kept its record", lock: withRecord(".lifecycle-txn.json", false), runs: true},
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
		// Loop round 2 (P1, P2) and round k: on every system the proc-start
		// record tells a live owner from a reused pid however the clock
		// stepped (a pid file dated a week back or ahead stands in for it).
		{name: "live owner with its proc-start record, clock stepped back", lock: withIdentity(false, 7*24*time.Hour)},
		{name: "live owner with its proc-start record, clock stepped ahead", lock: withIdentity(false, -7*24*time.Hour)},
		{name: "reused pid: another proc-start", lock: withIdentity(true, 0), runs: true},
		{name: "reused pid: another proc-start, clock stepped back", lock: withIdentity(true, 7*24*time.Hour), runs: true},
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
					// The PowerShell a Windows render names (the process start of a reused pid).
					WindowsPowerShellJS: javaScriptStringContent(windowsSystemPowerShellExe()),
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

// oss-outage-open round j loop round 2 (P2): both plugins held a lock that
// named their own pid, without asking when that process started, so a
// killed installer's pid the agent's process later reused held back every
// healthy answer of a strict or closed session for the whole session. No
// plugin writes a lock, and a live installer's pid names no other process:
// a lock naming the plugin's own pid is a reused pid, so the answer runs.
func TestPerUserPluginsTreatALockNamingTheirOwnPidAsStale(t *testing.T) {
	for _, plugin := range []struct{ name, asset, file, harness string }{
		{"opencode", "opencode-plugin.js", "defenseclaw.js", openCodeInstallWindowHarness},
		{"amp", "amp-plugin.ts", "defenseclaw.mts", ampInstallWindowHarness},
	} {
		t.Run(plugin.name, func(t *testing.T) {
			dataDir := testenv.PrivateTempDir(t)
			t.Setenv("DEFENSECLAW_HOME", testenv.PrivateTempDir(t))
			token := filepath.Join(dataDir, "hooks", ".hook-"+plugin.name+".token")
			if err := os.MkdirAll(filepath.Dir(token), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(token, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			rendered := writeRenderedPlugin(t, plugin.asset, plugin.file, templateData{
				APIAddr: "127.0.0.1:1", TokenFileJS: javaScriptStringContent(token), FailMode: "open",
				WindowsPowerShellJS: javaScriptStringContent(windowsSystemPowerShellExe()),
			})
			session := startNodeHarnessSession(t, plugin.harness, rendered, "valid-allow")
			lock := filepath.Join(dataDir, ".install.lock")
			if err := os.Mkdir(lock, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(lock, "pid"), []byte(strconv.Itoa(session.cmd.Process.Pid)+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			got := session.request("own pid", "call")
			session.close()
			if ran, _ := pluginStaleLockVerdict(t, plugin.name, got); !ran {
				t.Fatalf("healthy allow under a lock naming the plugin's own pid = %q; want it to run", got)
			}
		})
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
