// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0561: on the standalone profile the managed-hook lifecycle gates refuse
// file and folder drift the repair did not remove, and accept them once the
// repair made them trusted (the strict check runs again). The Secure Client
// twin is TestWindowsManagedHooksTrustRepairsThenAcceptsDrift.
func TestWindowsManagedHooksTrustStandaloneDrift(t *testing.T) {
	skipIfLocalSystem(t, "LocalSystem owns its t.TempDir() tree, so the fixture cannot stand in for a file a standard account owns")
	t.Setenv(managed.TrustStrictAncestorsEnv, "")
	t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
	originalEnsure := windowsManagedHooksEnsureCanonical
	t.Cleanup(func() { windowsManagedHooksEnsureCanonical = originalEnsure })

	fixtures := func(t *testing.T) (file, dir string) {
		t.Helper()
		dir = filepath.Join(t.TempDir(), "state")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		fileDir := t.TempDir()
		file = filepath.Join(fileDir, "managed-hooks-lifecycle-journal.json")
		if err := os.WriteFile(file, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		grantUntrustedWriterForTest(t, file)
		grantUntrustedWriterForTest(t, dir)
		return file, dir
	}

	t.Run("unrepaired drift is refused", func(t *testing.T) {
		file, dir := fixtures(t)
		calls := 0
		windowsManagedHooksEnsureCanonical = func(path string, kind managed.ObjectKind, _ managed.CanonicalOptions) (managed.CanonicalResult, error) {
			calls++
			return managed.CanonicalResult{Path: path, Kind: kind, Outcome: managed.CanonicalBoundary}, nil
		}
		if err := validateWindowsManagedHooksTrustedFile(file, managed.ObjectAdminFile, "lifecycle journal"); err == nil {
			t.Fatal("standalone accepted a lifecycle journal with an Everyone writer")
		}
		if err := validateWindowsManagedHooksTrustedDir(dir, managed.ObjectStateDirectory, "state root"); err == nil {
			t.Fatal("standalone accepted a state folder with an Everyone writer")
		}
		if calls != 2 {
			t.Fatalf("repair calls = %d, want 2", calls)
		}
	})

	t.Run("repaired drift is accepted", func(t *testing.T) {
		file, dir := fixtures(t)
		windowsManagedHooksEnsureCanonical = func(path string, kind managed.ObjectKind, _ managed.CanonicalOptions) (managed.CanonicalResult, error) {
			ownerOnlyDACLForTest(t, path)
			return managed.CanonicalResult{Path: path, Kind: kind, Outcome: managed.CanonicalRepaired}, nil
		}
		if err := validateWindowsManagedHooksTrustedFile(file, managed.ObjectAdminFile, "lifecycle journal"); err != nil {
			t.Fatalf("standalone refused a lifecycle journal the repair made trusted: %v", err)
		}
		if err := validateWindowsManagedHooksTrustedDir(dir, managed.ObjectStateDirectory, "state root"); err != nil {
			t.Fatalf("standalone refused a state folder the repair made trusted: %v", err)
		}
	})
}
