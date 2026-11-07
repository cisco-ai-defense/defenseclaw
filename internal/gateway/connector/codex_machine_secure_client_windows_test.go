// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// g582 round 9, Secure Client rule: the GAP-0650 changes (the writer lock, the
// transaction counter, the per-transaction state copies and the wait for a
// held requirements.toml) are standalone only. A Secure Client deployment
// that runs the Codex machine policy keeps the lock of 1.0.8 and earlier, the
// state at its fixed name and the behavior of a held requirements.toml it had
// before. These rows pin base behavior for opts.SecureClient.
func TestSecureClientCodexMachinePolicyKeepsTheLockAndStateOf108(t *testing.T) {
	row := windowsCodexRemovalRowsForTest[0]
	opts := newWindowsCodexMachineGuardFixtureForTest(t, row.requirements)
	opts.SecureClient = true
	dir := filepath.Dir(opts.RequirementsPath)
	if report, err := ReconcileWindowsCodexMachineRequirements(opts); err != nil || !report.OK {
		t.Fatalf("Secure Client reconcile: %+v, %v", report, err)
	}

	requireBase := func(when string) {
		t.Helper()
		if _, err := os.Lstat(filepath.Join(dir, windowsCodexManagedLegacyLockFile)); err != nil {
			t.Fatalf("%s: the lock of 1.0.8 is gone: %v", when, err)
		}
		if _, err := os.Lstat(filepath.Join(dir, WindowsCodexManagedWriterLockFile)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s: Secure Client created the writer lock: %v", when, err)
		}
		if data, err := os.ReadFile(opts.ManagedStatePath); err != nil || len(data) == 0 {
			t.Fatalf("%s: the state at its fixed name = %q, %v", when, data, err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if windowsCodexManagedStateCopyName(entry.Name()) {
				t.Fatalf("%s: Secure Client wrote the state copy %s", when, entry.Name())
			}
		}
	}
	requireBase("after reconcile")

	// The hook reads under the shared lock of 1.0.8 and gets the state.
	registry, err := ResolveWindowsCodexManagedRuntimeRegistry(opts.HookBinary)
	if err != nil || !registry.Active {
		t.Fatalf("the hook read %+v, %v; want the managed Codex state", registry, err)
	}

	// Verify and a second reconcile change nothing and add no copy.
	before, err := os.Stat(opts.ManagedStatePath)
	if err != nil {
		t.Fatal(err)
	}
	if report, err := VerifyWindowsCodexMachineRequirements(opts); err != nil || !report.OK {
		t.Fatalf("Secure Client verify: %+v, %v", report, err)
	}
	if report, err := ReconcileWindowsCodexMachineRequirements(opts); err != nil || !report.OK {
		t.Fatalf("Secure Client second reconcile: %+v, %v", report, err)
	}
	after, err := os.Stat(opts.ManagedStatePath)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("the state file was replaced by a read-only pass: %v", err)
	}
	requireBase("after verify and a second reconcile")

	// Removal deletes the state at its fixed name and takes no copy-based path.
	if report, err := RemoveWindowsCodexMachineRequirements(opts); err != nil || !report.OK {
		t.Fatalf("Secure Client removal: %+v, %v", report, err)
	}
	if _, err := os.Lstat(opts.ManagedStatePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the state stayed after the removal: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, WindowsCodexManagedWriterLockFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the removal created the writer lock: %v", err)
	}
}

// A requirements.toml a process holds open fails a Secure Client reconcile as
// it did before GAP-0650: the plain error, no named holder, no wait for the
// release.
func TestSecureClientCodexMachinePolicyDoesNotWaitForAHeldRequirements(t *testing.T) {
	row := windowsCodexRemovalRowsForTest[0]
	opts := newWindowsCodexMachineGuardFixtureForTest(t, row.requirements)
	opts.SecureClient = true
	if report, err := ReconcileWindowsCodexMachineRequirements(opts); err != nil || !report.OK {
		t.Fatalf("Secure Client reconcile: %+v, %v", report, err)
	}
	prependWindowsCodexRequirementForTest(t, opts.RequirementsPath, "admin_earlier")
	held := holdWindowsCodexFileForTest(t, opts.RequirementsPath, windows.FILE_SHARE_READ)
	defer windows.CloseHandle(held)
	changed, err := os.ReadFile(opts.RequirementsPath)
	if err != nil {
		t.Fatal(err)
	}

	previousSleep := windowsCodexHeldRetrySleep
	t.Cleanup(func() { windowsCodexHeldRetrySleep = previousSleep })
	windowsCodexHeldRetrySleep = func(time.Duration) { t.Error("a Secure Client reconcile waited for the held requirements.toml") }

	report, err := ReconcileWindowsCodexMachineRequirements(opts)
	var heldErr *WindowsCodexRequirementsHeldError
	if err == nil || errors.As(err, &heldErr) || report.OK || report.RequirementsHeldBy != "" {
		t.Fatalf("held requirements: %+v, %v; want the plain failure of 1.0.8, no named holder", report, err)
	}
	if after, readErr := os.ReadFile(opts.RequirementsPath); readErr != nil || !bytes.Equal(after, changed) {
		t.Fatalf("the held requirements changed: %v", readErr)
	}
}
