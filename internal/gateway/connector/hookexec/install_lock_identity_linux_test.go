// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// oss-outage-open round j loop round 2 (P1): Linux counts a process start
// from boot, so the start the lock rule compared with the pid file's time
// moved with the wall clock: a forward step of more than a minute during a
// live install made its owner look like a reused pid, and a default-tier
// outage opened mid-upgrade. install.sh now records its boot id and kernel
// start (proc-start); the rule compares that record as it is, and holds a
// lock without one while its pid names a process. A pid file written long
// before the owner's start stands in for the clock step.
func TestInstallLockIdentityTellsALiveOwnerAcrossAClockStep(t *testing.T) {
	live := os.Getppid()
	identity, ok := processIdentityOf(live)
	if !ok {
		t.Fatal("no identity for the parent process")
	}
	boot, ticks, _ := strings.Cut(identity, " ")
	n, err := strconv.ParseUint(ticks, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, record string
		write        bool
		held         bool
	}{
		{name: "live owner, its record, clock stepped forward", record: identity + "\n", write: true, held: true},
		{name: "live owner, no record (1.0.2/1.0.3), clock stepped forward", held: true},
		{name: "reused pid: another start", record: boot + " " + strconv.FormatUint(n+1, 10), write: true, held: false},
		{name: "reused pid: another boot", record: "00000000-0000-0000-0000-000000000000 " + ticks, write: true, held: false},
		{name: "empty record", record: " ", write: true, held: true},
		{name: "record too long", record: strings.Repeat("a", 200), write: true, held: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			lock := filepath.Join(home, ".install.lock")
			if err := os.Mkdir(lock, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(lock, "pid"), []byte(strconv.Itoa(live)+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			then := time.Now().Add(-7 * time.Hour)
			if err := os.Chtimes(filepath.Join(lock, "pid"), then, then); err != nil {
				t.Fatal(err)
			}
			if tc.write {
				if err := os.WriteFile(filepath.Join(lock, InstallLockIdentityName), []byte(tc.record), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if got := InstallLockHeld(home); got != tc.held {
				t.Fatalf("InstallLockHeld = %v, want %v", got, tc.held)
			}
		})
	}
	t.Run("a record that is a folder", func(t *testing.T) {
		home := t.TempDir()
		lock := filepath.Join(home, ".install.lock")
		if err := os.MkdirAll(filepath.Join(lock, InstallLockIdentityName), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(lock, "pid"), []byte(strconv.Itoa(live)), 0o600); err != nil {
			t.Fatal(err)
		}
		if !InstallLockHeld(home) {
			t.Fatal("a record that cannot be read must hold")
		}
	})
}

// processIdentityOf reads the boot id and field 22 of /proc/<pid>/stat.
func TestProcessIdentityOfNamesBootAndStart(t *testing.T) {
	identity, ok := processIdentityOf(os.Getpid())
	if !ok {
		t.Fatal("no identity for this process")
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	stat, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		t.Fatal(err)
	}
	ticks, _ := parseProcStatStartTicks(string(stat))
	if want := strings.TrimSpace(string(boot)) + " " + strconv.FormatUint(ticks, 10); identity != want {
		t.Fatalf("processIdentityOf = %q, want %q", identity, want)
	}
	if _, ok := processIdentityOf(2147483647); ok {
		t.Fatal("an identity for a pid that names no process")
	}
}
