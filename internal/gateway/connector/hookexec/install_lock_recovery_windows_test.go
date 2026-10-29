// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookexec

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// install.ps1 may leave its lock when rollback still needs attention. Once
// the owning installer exits, that marker cannot close every per-user hook.
func TestWindowsRecoveryPendingLockDoesNotOutliveInstaller(t *testing.T) {
	for _, tc := range []struct {
		name, pid string
		age       time.Duration
	}{
		{"installer exited", "99999999", 0},
		{"owner reused after ten minutes", strconv.Itoa(os.Getpid()), 11 * time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := t.TempDir()
			if err := os.Mkdir(filepath.Join(data, ".rollback-hold"), 0o700); err != nil {
				t.Fatal(err)
			}
			lock := filepath.Join(data, installLockName)
			if err := os.Mkdir(lock, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(lock, "pid"), []byte(tc.pid+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if tc.age != 0 {
				then := time.Now().Add(-tc.age)
				if err := os.Chtimes(lock, then, then); err != nil {
					t.Fatal(err)
				}
			}
			if InstallLockHeld(data) {
				t.Fatal("recovery-pending lock still blocks after its owner ended or its age cap passed")
			}
		})
	}
}
