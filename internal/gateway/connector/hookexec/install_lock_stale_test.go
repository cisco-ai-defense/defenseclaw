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

// oss-outage-open round i (stale lock class): an installer killed after it
// made .install.lock left the lock, and every native hook, hook-outage-mode
// and the shell hooks then closed every outage of a default-tier account for
// good. The lock records its owner (pid, start time) and a deadline; a lock
// whose deadline has passed, or whose owner is proven gone, is no lock. A
// live or uncertain owner, or an interrupted install's kept lock before its
// deadline, still holds it.
func TestInstallLockHeldIgnoresALockWhoseOwnerIsGoneOrWhoseDeadlinePassed(t *testing.T) {
	exited := exec.Command(os.Args[0], "-test.run=^$")
	if err := exited.Run(); err != nil {
		t.Fatal(err)
	}
	dead := strconv.Itoa(exited.ProcessState.Pid())
	live := strconv.Itoa(os.Getppid())
	now := time.Now()
	past := strconv.FormatInt(now.Add(-time.Minute).Unix(), 10)
	future := strconv.FormatInt(now.Add(time.Hour).Unix(), 10)
	farFuture := strconv.FormatInt(now.Add(100*24*time.Hour).Unix(), 10)
	type owner struct {
		pid, deadline string
		age           time.Duration
		record        string
	}
	for _, tc := range []struct {
		name string
		lock owner
		held bool
	}{
		{"installer exited", owner{pid: dead + "\n"}, false},
		{"installer exited, Windows line end", owner{pid: dead + "\r\n"}, false},
		{"installer exited, deadline ahead", owner{pid: dead + "\n", deadline: future}, false},
		{"installer running", owner{pid: live + "\n", deadline: future}, true},
		{"installer running, no deadline recorded", owner{pid: live + "\n"}, true},
		{"installer running, deadline passed", owner{pid: live + "\n", deadline: past}, false},
		{"installer running, recorded deadline past the six-hour bound", owner{pid: live, deadline: farFuture, age: 7 * time.Hour}, false},
		{"installer running, made seven hours ago", owner{pid: live, age: 7 * time.Hour}, false},
		{"no pid yet", owner{}, true},
		{"empty pid", owner{pid: " "}, true},
		{"no pid for eleven minutes", owner{age: 11 * time.Minute}, false},
		{"pid not a number", owner{pid: "abc"}, true},
		{"pid out of range, fresh", owner{pid: "99999999999"}, true},
		{"pid out of range for eleven minutes", owner{pid: "99999999999", age: 11 * time.Minute}, false},
		{"deadline not a number, installer exited", owner{pid: dead, deadline: "soon"}, false},
		{"interrupted install kept previous.new", owner{pid: dead, record: "previous.new"}, true},
		{"interrupted install kept .repair", owner{pid: dead, record: ".repair"}, true},
		{"interrupted install kept .rollback-hold", owner{pid: dead, record: ".rollback-hold"}, true},
		{"interrupted Windows install kept its record", owner{pid: dead, record: ".lifecycle-txn.json"}, true},
		{"interrupted install past its deadline", owner{pid: dead, record: "previous.new", deadline: past}, false},
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
	t.Run("pid or deadline that is a folder", func(t *testing.T) {
		for _, name := range []string{"pid", "deadline"} {
			home := t.TempDir()
			if err := os.MkdirAll(filepath.Join(home, ".install.lock", name), 0o700); err != nil {
				t.Fatal(err)
			}
			if !InstallLockHeld(home) {
				t.Fatalf("a %s record that cannot be read must hold", name)
			}
		}
	})
}
