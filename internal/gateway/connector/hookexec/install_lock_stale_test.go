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

// oss-outage-open round i (stale lock class) and round j (one liveness
// rule): a lock is no lock only when its owner is gone: its pid names no
// process, or a process that started after the pid was written (a reused
// pid; also the PID-only lock of 1.0.2 and 1.0.3, GAP-1465), or it has had
// no pid for ten minutes. A live owner keeps it for as long as it runs: a
// lock made seven hours ago, or a deadline an earlier build recorded, no
// longer expires it (round i loop 2 P1). An uncertain owner or an
// interrupted install's kept lock holds.
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
	now := time.Now()
	past := strconv.FormatInt(now.Add(-time.Minute).Unix(), 10)
	type owner struct {
		pid, deadline string
		age, pidAge   time.Duration
		record        string
	}
	for _, tc := range []struct {
		name string
		lock owner
		held bool
	}{
		{"installer exited", owner{pid: dead + "\n"}, false},
		{"installer exited, Windows line end", owner{pid: dead + "\r\n"}, false},
		{"installer running", owner{pid: live + "\n"}, true},
		{"installer running, lock made seven hours ago", owner{pid: live, age: 7 * time.Hour}, true},
		{"installer running, a deadline an earlier build recorded has passed", owner{pid: live, deadline: past, age: 7 * time.Hour}, true},
		{"pid reused: its process started after the pid was written", owner{pid: live, age: 7 * time.Hour, pidAge: 7 * time.Hour}, false},
		{"1.0.2/1.0.3 PID-only lock, pid reused an hour after it was written (GAP-1465)", owner{pid: live, age: time.Hour, pidAge: time.Hour}, false},
		{"1.0.2/1.0.3 PID-only lock, installer exited", owner{pid: dead, age: time.Hour, pidAge: time.Hour}, false},
		{"1.0.2/1.0.3 PID-only lock, pid reused", owner{pid: live, age: 30 * 24 * time.Hour, pidAge: 30 * 24 * time.Hour}, false},
		{"1.0.2/1.0.3 PID-only lock, installer running", owner{pid: live}, true},
		{"no pid yet", owner{}, true},
		{"empty pid", owner{pid: " "}, true},
		{"no pid for eleven minutes", owner{age: 11 * time.Minute}, false},
		{"pid not a number", owner{pid: "abc"}, true},
		{"pid out of range, fresh", owner{pid: "99999999999"}, true},
		{"pid out of range for eleven minutes", owner{pid: "99999999999", age: 11 * time.Minute}, false},
		{"interrupted install kept previous.new", owner{pid: dead, record: "previous.new"}, true},
		{"interrupted install kept .repair", owner{pid: dead, record: ".repair"}, true},
		{"interrupted install kept .rollback-hold", owner{pid: dead, record: ".rollback-hold"}, true},
		{"interrupted Windows install kept its record", owner{pid: dead, record: ".lifecycle-txn.json"}, true},
		{"interrupted install, an earlier build's deadline passed", owner{pid: dead, record: "previous.new", deadline: past}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
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
			if tc.lock.pidAge > 0 {
				then := now.Add(-tc.lock.pidAge)
				if err := os.Chtimes(filepath.Join(lock, "pid"), then, then); err != nil {
					t.Fatal(err)
				}
			}
			if tc.lock.record != "" {
				if err := os.Mkdir(filepath.Join(home, tc.lock.record), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if tc.lock.age > 0 {
				then := now.Add(-tc.lock.age)
				if err := os.Chtimes(lock, then, then); err != nil {
					t.Fatal(err)
				}
			}
			if got := InstallLockHeld(home); got != tc.held {
				t.Fatalf("InstallLockHeld = %v, want %v", got, tc.held)
			}
			opts := Options{Home: home, FailMode: "open"}
			if got := closeDuringInstall(&opts, "open"); (got == "closed") != tc.held {
				t.Fatalf("closeDuringInstall = %q with the lock held %v", got, tc.held)
			}
		})
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

// The start-time reader names the start of another live process, and it is
// no later than now.
func TestProcessStartTimeOfAnotherProcess(t *testing.T) {
	started, known := processStartTimeOf(os.Getppid(), time.Now())
	if !processStartTimeKnown {
		if known {
			t.Fatal("a system without a start-time reader named one")
		}
		return
	}
	if !known {
		t.Fatal("no start time for the parent process")
	}
	if started.After(time.Now().Add(time.Second)) || started.Before(time.Now().Add(-30*24*time.Hour)) {
		t.Fatalf("parent start %s is not plausible", started)
	}
}
