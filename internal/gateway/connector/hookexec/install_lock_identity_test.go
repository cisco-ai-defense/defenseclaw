// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/procidentity"
)

// otherIdentity is identity with its last digit changed: the record of
// another process that had the same pid (a reused pid).
func otherIdentity(identity string) string {
	last := identity[len(identity)-1]
	return identity[:len(identity)-1] + string(rune('0'+(last-'0'+1)%10))
}

// oss-outage-open round k (rules 1 and 3): the owner is named only by its
// identity, the pid's process start as the system keeps it (Linux boot id
// and kernel start, macOS creation second, Windows creation FILETIME), so
// the answer is the same however the wall clock stepped: a pid file written
// a week before or after the owner started (a step either way) changes
// nothing. A live owner with its record holds; the same pid with another
// record is a reused pid, a dead lock, on every system (round j loop 2 P1
// and P2: a clock step made a live macOS or Windows owner look reused, and a
// reused pid held a dead lock for a whole session).
func TestInstallLockIdentityTellsALiveOwnerAcrossAClockStep(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skip("no process identity reader on " + runtime.GOOS)
	}
	live := os.Getppid()
	identity, ok := procidentity.Of(live)
	if !ok {
		t.Fatal("no identity for the parent process")
	}
	for _, tc := range []struct {
		name, record string
		write        bool
		held         bool
		legacy       bool
	}{
		{name: "live owner, its record", record: identity + "\n", write: true, held: true},
		{name: "live owner, its record, Windows line end", record: identity + "\r\n", write: true, held: true},
		// Dated a week back, the lock is older than its pid's process: a
		// reused pid (GAP-1465).
		{name: "live owner, no record (1.0.2/1.0.3)", held: true, legacy: true},
		{name: "reused pid: another process's record", record: otherIdentity(identity), write: true, held: false},
		{name: "empty record", record: " ", write: true, held: true},
		{name: "record too long", record: strings.Repeat("a", 200), write: true, held: true},
	} {
		for _, step := range []time.Duration{0, -7 * 24 * time.Hour, 7 * 24 * time.Hour} {
			t.Run(tc.name+"/pid written "+step.String(), func(t *testing.T) {
				home := t.TempDir()
				lock := filepath.Join(home, ".install.lock")
				if err := os.Mkdir(lock, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(lock, "pid"), []byte(strconv.Itoa(live)+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if tc.write {
					if err := os.WriteFile(filepath.Join(lock, InstallLockIdentityName), []byte(tc.record), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				if step != 0 {
					then := time.Now().Add(step)
					for _, path := range []string{filepath.Join(lock, "pid"), filepath.Join(lock, InstallLockIdentityName), lock} {
						if err := os.Chtimes(path, then, then); err != nil && !os.IsNotExist(err) {
							t.Fatal(err)
						}
					}
				}
				held := tc.held && !(tc.legacy && step < 0)
				if got := InstallLockHeld(home); got != held {
					t.Fatalf("InstallLockHeld = %v, want %v", got, held)
				}
			})
		}
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
