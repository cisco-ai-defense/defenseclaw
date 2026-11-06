// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0561: on the standalone profile the managed-hook lifecycle and teardown
// journals are never repaired in place: a drifted journal is refused with the
// strict verdict. A folder another account can write or owns is refused the
// same way (g582 round 4, E6); a folder with trusted-only drift keeps the
// repair-then-recheck rule. The Secure Client twin is
// TestWindowsManagedHooksTrustRepairsThenAcceptsDrift.
func TestWindowsManagedHooksTrustStandaloneDrift(t *testing.T) {
	requireAdministratorTestToken(t, "the product trusts only administrator-owned state folders; a standard user's test folder is untrusted by design")
	skipIfLocalSystem(t, "LocalSystem owns its t.TempDir() tree, so the fixture cannot stand in for a file a standard account owns")
	t.Setenv(managed.TrustStrictAncestorsEnv, "")
	t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
	originalEnsure := windowsManagedHooksEnsureCanonical
	t.Cleanup(func() { windowsManagedHooksEnsureCanonical = originalEnsure })
	calls := 0
	windowsManagedHooksEnsureCanonical = func(path string, kind managed.ObjectKind, _ managed.CanonicalOptions) (managed.CanonicalResult, error) {
		calls++
		ownerOnlyDACLForTest(t, path)
		return managed.CanonicalResult{Path: path, Kind: kind, Outcome: managed.CanonicalRepaired}, nil
	}

	journal := filepath.Join(t.TempDir(), "managed-hooks-lifecycle-journal.json")
	teardown := filepath.Join(t.TempDir(), windowsManagedHooksTeardownJournalFile)
	for _, path := range []string{journal, teardown} {
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		grantUntrustedWriterForTest(t, path)
	}
	if err := validateWindowsManagedHooksTrustedFile(journal, managed.ObjectAdminFile, "lifecycle journal"); err == nil ||
		!strings.Contains(err.Error(), `.\DefenseClawSetup-Enterprise-Standalone-x64.exe' /ensure`) {
		t.Fatalf("drifted lifecycle journal = %v, want the strict refusal and the Setup step", err)
	}
	if err := validateWindowsManagedHooksTeardownJournalFile(teardown); err == nil {
		t.Fatal("standalone accepted a drifted teardown journal")
	}
	if calls != 0 {
		t.Fatalf("repair calls = %d, want none for standalone journals", calls)
	}

	t.Run("folder drift with an untrusted writer is refused, not repaired", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "state")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		grantUntrustedWriterForTest(t, dir)
		before := calls
		err := validateWindowsManagedHooksTrustedDir(dir, managed.ObjectStateDirectory, "state root")
		var refused *managed.StandaloneContentDriftError
		if !errors.As(err, &refused) || !strings.Contains(err.Error(), "/remove:g") {
			t.Fatalf("standalone state folder with an Everyone writer = %v, want the standalone refusal", err)
		}
		if calls != before {
			t.Fatalf("repair calls = %d, want none for an untrusted state folder", calls-before)
		}
	})
	t.Run("trusted-only folder drift is repaired and rechecked", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "state")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := validateWindowsManagedHooksTrustedDir(dir, managed.ObjectStateDirectory, "state root"); err != nil {
			t.Fatalf("standalone refused a state folder the repair made trusted: %v", err)
		}
	})
	t.Run("unrepaired folder drift is refused", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "state")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		grantUntrustedWriterForTest(t, dir)
		windowsManagedHooksEnsureCanonical = func(path string, kind managed.ObjectKind, _ managed.CanonicalOptions) (managed.CanonicalResult, error) {
			return managed.CanonicalResult{Path: path, Kind: kind, Outcome: managed.CanonicalBoundary}, nil
		}
		if err := validateWindowsManagedHooksTrustedDir(dir, managed.ObjectStateDirectory, "state root"); err == nil {
			t.Fatal("standalone accepted a state folder with an Everyone writer")
		}
	})
}
