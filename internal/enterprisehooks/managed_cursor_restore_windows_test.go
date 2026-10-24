// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
)

// GAP-0028: a refused uninstall rolls its managed-hook teardown back. With
// Cursor not enrolled, the teardown never touches an administrator's own
// C:\ProgramData\Cursor\hooks.json, so the rollback must not rewrite it
// either. It used to write the file back and re-apply its descriptor, then
// require DefenseClaw's file trust of it; an administrator's folder inherits
// ProgramData's user-create grant and fails that check, so the rollback
// failed and the uninstall stayed pending with every service disabled.
//
// Standalone only: a Secure Client process keeps the earlier restore, which
// writes the file back (Secure Client is out of scope for this fix).
func TestWindowsCursorInactiveRestoreLeavesAnUntouchedAdministratorFile(t *testing.T) {
	originalTrust := windowsManagedPolicyFileTrustCheck
	originalRoot := windowsCursorManagedRootResolver
	originalWriter := windowsManagedPolicyWriter
	originalSwap := windowsCursorManagedFileSwap
	originalStandalone := windowsEnterpriseStandaloneProcess
	windowsEnterpriseStandaloneProcess = func() bool { return true }
	root := t.TempDir() + `\Cursor`
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	windowsCursorManagedRootResolver = func() (string, error) { return root, nil }
	paths, err := windowsCursorManagedPaths()
	if err != nil {
		t.Fatal(err)
	}
	windowsManagedPolicyFileTrustCheck = func(path string) error {
		if strings.EqualFold(path, paths.Hooks) {
			return errors.New("the administrator's Cursor folder is writable by standard users")
		}
		return nil
	}
	var writes []string
	windowsManagedPolicyWriter = func(path string, data []byte, userReadable bool) error {
		writes = append(writes, path)
		return originalWriter(path, data, userReadable)
	}
	// hooks.json is restored through a compare-and-swap.
	windowsCursorManagedFileSwap = func(request windowsCursorManagedSwap) (windowsCursorManagedSwapResult, error) {
		writes = append(writes, request.path)
		return originalSwap(request)
	}
	t.Cleanup(func() {
		windowsManagedPolicyFileTrustCheck = originalTrust
		windowsCursorManagedRootResolver = originalRoot
		windowsManagedPolicyWriter = originalWriter
		windowsCursorManagedFileSwap = originalSwap
		windowsEnterpriseStandaloneProcess = originalStandalone
	})

	admin := []byte(`{"version":1,"hooks":{"beforeShellExecution":[{"command":"C:\\Tools\\audit.exe"}]}}`)
	if err := os.WriteFile(paths.Hooks, admin, 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := snapshotWindowsCursorManagedArtifacts()
	if err != nil {
		t.Fatal(err)
	}
	validated, err := validateWindowsCursorManagedArtifacts(before)
	if err != nil || validated.active {
		t.Fatalf("the administrator's hooks.json must read as an inactive policy: active=%t err=%v", validated.active, err)
	}
	snapshot := windowsCursorManagedTeardownSnapshot(validated)

	// The body of RestoreWindowsCursorManagedPolicyTeardown, without the
	// transaction lock, which needs a protected ProgramData folder.
	current, err := snapshotWindowsCursorManagedArtifacts()
	if err != nil {
		t.Fatal(err)
	}
	if err := restoreWindowsCursorManagedSnapshotUnlocked(
		WindowsCursorManagedPolicyTeardownOptions{}, snapshot, current, true,
	); err != nil {
		t.Fatalf("rollback of an untouched inactive Cursor policy failed: %v", err)
	}
	if len(writes) != 0 {
		t.Fatalf("rollback rewrote files it never changed: %v", writes)
	}
	after, err := snapshotWindowsCursorManagedArtifacts()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after.hooks.data, admin) || after.hooksMetadata != before.hooksMetadata {
		t.Fatalf("administrator hooks.json changed: %q %+v, want %q %+v",
			after.hooks.data, after.hooksMetadata, admin, before.hooksMetadata)
	}

	// Secure Client keeps the earlier restore: every file is written back.
	windowsEnterpriseStandaloneProcess = func() bool { return false }
	current, err = snapshotWindowsCursorManagedArtifacts()
	if err != nil {
		t.Fatal(err)
	}
	_ = restoreWindowsCursorManagedSnapshotUnlocked(
		WindowsCursorManagedPolicyTeardownOptions{}, snapshot, current, true,
	)
	if len(writes) == 0 {
		t.Fatal("a Secure Client restore no longer writes the administrator's hooks.json back")
	}
}
