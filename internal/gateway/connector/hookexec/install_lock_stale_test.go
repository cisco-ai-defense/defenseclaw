// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// oss-outage-open rounds i to k (one liveness rule, no clock): a lock is no
// lock only when its owner is gone: its pid names no process, or the
// reader's own, or another process than its proc-start record names. A
// live owner keeps it for as long as it runs; so does a lock without a
// valid pid, and a 1.0.2/1.0.3 lock without a record whose pid names a
// process. The lock's age, its pid file's time and a deadline an earlier
// build recorded are never read: every row runs with each of them a week in
// the past and a week in the future (a wall-clock step either way).
func TestInstallLockHeldIgnoresOnlyALockWhoseOwnerIsGone(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	exited := exec.Command(self, "-test.run=^$")
	if err := exited.Run(); err != nil {
		t.Fatal(err)
	}
	dead := strconv.Itoa(exited.ProcessState.Pid())
	live := strconv.Itoa(os.Getppid())
	type owner struct {
		pid, deadline, record string
	}
	// legacy: a lock without a proc-start record whose pid names a live
	// process. Dated a week back, that process started after the lock: its
	// pid was reused and the lock is stale (LEAD DECISION 13:58, GAP-1465).
	for _, tc := range []struct {
		name   string
		lock   owner
		held   bool
		legacy bool
	}{
		{"installer exited", owner{pid: dead + "\n"}, false, false},
		{"installer exited, Windows line end", owner{pid: dead + "\r\n"}, false, false},
		{"installer running", owner{pid: live + "\n"}, true, true},
		{"installer running, a deadline an earlier build recorded", owner{pid: live, deadline: "1"}, true, true},
		// Without a proc-start record no clock may tell a reused pid from a
		// live owner: a 1.0.2/1.0.3 PID-only lock holds while its pid names
		// a process (GAP-1465 is the reused pid of a lock with a record).
		{"1.0.2/1.0.3 PID-only lock, its pid names a process", owner{pid: live}, true, true},
		{"1.0.2/1.0.3 PID-only lock, installer exited", owner{pid: dead}, false, false},
		// Loop round 2 P2: no reader writes a lock, so a lock naming the
		// reader's own pid is a reused pid.
		{"lock names this reader's own pid", owner{pid: strconv.Itoa(os.Getpid())}, false, false},
		// Round k: a lock without a valid pid holds; no wait expires it.
		{"no pid", owner{}, true, false},
		{"empty pid", owner{pid: " "}, true, false},
		{"pid not a number", owner{pid: "abc"}, true, false},
		{"pid out of range", owner{pid: "99999999999"}, true, false},
		// GAP-1024: an interrupted-install record does not hold the lock
		// once its installer is gone.
		{"interrupted install kept previous.new", owner{pid: dead, record: "previous.new"}, false, false},
		{"interrupted install kept .repair", owner{pid: dead, record: ".repair"}, false, false},
		{"interrupted install kept .rollback-hold", owner{pid: dead, record: ".rollback-hold"}, false, false},
		{"interrupted Windows install kept its record", owner{pid: dead, record: ".lifecycle-txn.json"}, false, false},
		{"interrupted install, an earlier build's deadline", owner{pid: dead, record: "previous.new", deadline: "1"}, false, false},
	} {
		for _, step := range []time.Duration{0, -7 * 24 * time.Hour, 7 * 24 * time.Hour} {
			t.Run(tc.name+"/times "+step.String(), func(t *testing.T) {
				home := t.TempDir()
				lock := filepath.Join(home, ".install.lock")
				if err := os.Mkdir(lock, 0o700); err != nil {
					t.Fatal(err)
				}
				for name, value := range map[string]string{"pid": tc.lock.pid, "deadline": tc.lock.deadline} {
					if value == "" {
						continue
					}
					if err := os.WriteFile(filepath.Join(lock, name), []byte(value), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				if tc.lock.record != "" {
					if err := os.Mkdir(filepath.Join(home, tc.lock.record), 0o700); err != nil {
						t.Fatal(err)
					}
				}
				if step != 0 {
					then := time.Now().Add(step)
					for _, path := range []string{filepath.Join(lock, "pid"), lock} {
						if err := os.Chtimes(path, then, then); err != nil && !os.IsNotExist(err) {
							t.Fatal(err)
						}
					}
				}
				held := tc.held && (!tc.legacy || step >= 0)
				if got := InstallLockHeld(home); got != held {
					t.Fatalf("InstallLockHeld = %v, want %v", got, held)
				}
				opts := Options{Home: home, FailMode: "open"}
				if got := closeDuringInstall(&opts, "open"); (got == "closed") != held {
					t.Fatalf("closeDuringInstall = %q with the lock held %v", got, held)
				}
			})
		}
	}
	t.Run("lock that is a file", func(t *testing.T) {
		home := t.TempDir()
		if err := os.WriteFile(filepath.Join(home, ".install.lock"), []byte(dead), 0o600); err != nil {
			t.Fatal(err)
		}
		if !InstallLockHeld(home) {
			t.Fatal("a lock that is not a folder must hold")
		}
	})
	t.Run("pid that is a folder", func(t *testing.T) {
		home := t.TempDir()
		if err := os.MkdirAll(filepath.Join(home, ".install.lock", "pid"), 0o700); err != nil {
			t.Fatal(err)
		}
		if !InstallLockHeld(home) {
			t.Fatal("a pid record that cannot be read must hold")
		}
	})
}

// GAP-2082: a pending recovery (lock + interrupted-install record) is read
// by what would start the install, never by a hook's allow or deny: the lock
// of a dead installer stays free for the hooks (GAP-1024) while
// InstallRecoveryPending reports the recovery.
func TestInstallRecoveryPendingNeedsTheLockAndARecord(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	exited := exec.Command(self, "-test.run=^$")
	if err := exited.Run(); err != nil {
		t.Fatal(err)
	}
	dead := strconv.Itoa(exited.ProcessState.Pid())
	for _, tc := range []struct {
		name          string
		lock, pending bool
		record        string
	}{
		{"no lock, no record", false, false, ""},
		{"record without a lock", false, false, "previous.new"},
		{"lock without a record", true, false, ""},
		{"lock and previous.new", true, true, "previous.new"},
		{"lock and .repair", true, true, ".repair"},
		{"lock and .rollback-hold", true, true, ".rollback-hold"},
		{"lock and .lifecycle-txn.json", true, true, ".lifecycle-txn.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			if tc.lock {
				lock := filepath.Join(home, ".install.lock")
				if err := os.Mkdir(lock, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(lock, "pid"), []byte(dead+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.record != "" {
				if err := os.WriteFile(filepath.Join(home, tc.record), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if got := InstallRecoveryPending(home); got != tc.pending {
				t.Fatalf("InstallRecoveryPending = %v, want %v", got, tc.pending)
			}
			if InstallLockHeld(home) {
				t.Fatal("a dead installer's lock holds the hooks (GAP-1024)")
			}
		})
	}
	if InstallRecoveryPending("") || InstallRecoveryPending(" ") {
		t.Fatal("an empty home reports a recovery")
	}
}
