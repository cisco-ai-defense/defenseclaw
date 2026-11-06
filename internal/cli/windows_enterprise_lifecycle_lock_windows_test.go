// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// The production lifecycle.lock seams, read at package initialization,
// before the test sandbox (isolateTestRunFolders) points them at a missing
// lock, so the test below checks what ships.
var (
	productionWindowsSecretLifecycleLock     = windowsSecretLifecycleLock
	productionWindowsEnterpriseHotConfigLock = windowsEnterpriseHotConfigLock
)

// GAP-0646 review 2: only the hot-config seam (Setup's pre-step, hot apply,
// bundle restore, generation repair) waits for a held lifecycle.lock. The
// guardian's per-user Claude transaction-folder cleanup and the secret
// store's take return at once, so a lifecycle run never costs a guardian pass
// the wait per user, and the secret store's own wait is not stretched.
func TestOnlyTheHotConfigSeamWaitsForLifecycleLock(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "lifecycle.lock")
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	release, err := tryWindowsEnterpriseLifecycleLock(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
	saved := windowsEnterpriseLifecycleLockWait
	t.Cleanup(func() { windowsEnterpriseLifecycleLockWait = saved })
	windowsEnterpriseLifecycleLockWait = 30 * time.Second

	folder := filepath.Join(dir, "claude-settings-teardown")
	if err := os.Mkdir(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := removeWindowsManagedClaudeTransactionFolderOutsideLifecycle(folder, lockPath); err != nil {
		t.Fatalf("cleanup while a run holds lifecycle.lock = %v, want nil (nothing to do)", err)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("the per-user cleanup waited %v for a held lifecycle.lock, want it to return at once", took)
	}
	if _, err := os.Stat(folder); err != nil {
		t.Fatalf("the cleanup removed the folder while a run held lifecycle.lock: %v", err)
	}

	start = time.Now()
	if unlock, err := productionWindowsSecretLifecycleLock(lockPath); !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		if unlock != nil {
			unlock()
		}
		t.Fatalf("secret store take of a held lifecycle.lock = %v, want a sharing violation", err)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("the secret store's single take waited %v, want it to return at once", took)
	}

	windowsEnterpriseLifecycleLockWait = 300 * time.Millisecond
	start = time.Now()
	if unlock, err := productionWindowsEnterpriseHotConfigLock(lockPath); !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		if unlock != nil {
			unlock()
		}
		t.Fatalf("hot-config take of a held lifecycle.lock = %v, want busy after the wait", err)
	}
	if took := time.Since(start); took < 300*time.Millisecond {
		t.Fatalf("the hot-config seam gave up after %v, want it to wait windowsEnterpriseLifecycleLockWait", took)
	}
}
