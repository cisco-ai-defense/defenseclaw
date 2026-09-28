// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func stubWindowsHookRuntimeRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "DefenseClaw-HookRuntime")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	previousRoot, previousDir, previousStandalone := windowsStandaloneHookRuntimeRoot, windowsPerUserManagedRuntimeDirResolver, windowsEnterpriseStandaloneProcess
	windowsStandaloneHookRuntimeRoot = func() (string, error) { return root, nil }
	windowsPerUserManagedRuntimeDirResolver = func(name string) (string, error) { return filepath.Join(root, name), nil }
	windowsEnterpriseStandaloneProcess = func() bool { return true }
	t.Cleanup(func() {
		windowsStandaloneHookRuntimeRoot, windowsPerUserManagedRuntimeDirResolver, windowsEnterpriseStandaloneProcess = previousRoot, previousDir, previousStandalone
	})
	return root
}

// Revoking enrollments during an uninstall must not create a runtime
// directory and lock file for connectors that never ran.
func TestRemoveWindowsPerUserManagedEnrollmentsCreatesNothingForUnusedConnectors(t *testing.T) {
	root := stubWindowsHookRuntimeRoot(t)
	if err := RemoveWindowsPerUserManagedEnrollments(`C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`, WindowsStandalonePerUserConnectorNames()); err != nil {
		t.Fatalf("RemoveWindowsPerUserManagedEnrollments: %v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("revocation created %d entries under the hook runtime directory, first %s", len(entries), entries[0].Name())
	}
}

func writeHookRuntimeFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRemoveWindowsStandaloneHookRuntimeDirectoriesRemovesOnlyEmptiedDirectories(t *testing.T) {
	root := stubWindowsHookRuntimeRoot(t)
	writeHookRuntimeFile(t, filepath.Join(root, "copilot", windowsPerUserManagedEnrollmentLockFile))
	writeHookRuntimeFile(t, filepath.Join(root, "copilot", windowsManagedRuntimeSelectorLockFile))
	writeHookRuntimeFile(t, filepath.Join(root, "devin", windowsPerUserManagedEnrollmentLockFile))
	enrollment := filepath.Join(root, "devin", windowsPerUserManagedEnrollmentFile)
	writeHookRuntimeFile(t, enrollment)

	kept, err := RemoveWindowsStandaloneHookRuntimeDirectories()
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "copilot")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a directory holding only lock files must be removed: %v", err)
	}
	if _, err := os.Lstat(enrollment); err != nil {
		t.Fatalf("a directory with an enrollment must be left untouched: %v", err)
	}
	if len(kept) != 2 {
		t.Fatalf("kept = %v, want the devin directory and the root", kept)
	}

	if err := os.Remove(enrollment); err != nil {
		t.Fatal(err)
	}
	if kept, err := RemoveWindowsStandaloneHookRuntimeDirectories(); err != nil || len(kept) != 0 {
		t.Fatalf("second cleanup kept=%v err=%v, want everything removed", kept, err)
	}
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the emptied hook runtime root must be removed: %v", err)
	}
	if kept, err := RemoveWindowsStandaloneHookRuntimeDirectories(); err != nil || len(kept) != 0 {
		t.Fatalf("cleanup of an absent root kept=%v err=%v", kept, err)
	}
}

func TestRemoveWindowsStandaloneHookRuntimeDirectoriesIsStandaloneOnly(t *testing.T) {
	root := stubWindowsHookRuntimeRoot(t)
	windowsEnterpriseStandaloneProcess = func() bool { return false }
	if _, err := RemoveWindowsStandaloneHookRuntimeDirectories(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(root); err != nil {
		t.Fatalf("a Secure Client process must not touch the standalone hook runtime directory: %v", err)
	}
}
