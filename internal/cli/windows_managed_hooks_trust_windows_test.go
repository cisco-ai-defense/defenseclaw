// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// stubWindowsManagedHooksTrust makes the strict checks report drift and
// records each EnsureCanonical call; the tolerant fallback runs for real
// against a temp file, which a non-admin test user owns.
func stubWindowsManagedHooksTrust(t *testing.T, outcome managed.CanonicalOutcome, ensureErr error) *[]managed.ObjectKind {
	t.Helper()
	ensured := []managed.ObjectKind{}
	originalEnsure := windowsManagedHooksEnsureCanonical
	originalFile := windowsManagedHooksStrictFileCheck
	originalDir := windowsManagedHooksStrictDirCheck
	t.Cleanup(func() {
		windowsManagedHooksEnsureCanonical = originalEnsure
		windowsManagedHooksStrictFileCheck = originalFile
		windowsManagedHooksStrictDirCheck = originalDir
	})
	drift := errors.New("owner S-1-5-21-1-2-3-1001 is not trusted")
	windowsManagedHooksStrictFileCheck = func(string, string) error { return drift }
	windowsManagedHooksStrictDirCheck = func(string, string) error { return drift }
	windowsManagedHooksEnsureCanonical = func(path string, kind managed.ObjectKind, _ managed.CanonicalOptions) (managed.CanonicalResult, error) {
		ensured = append(ensured, kind)
		return managed.CanonicalResult{Path: path, Kind: kind, Outcome: outcome}, ensureErr
	}
	return &ensured
}

func TestWindowsManagedHooksTrustRepairsThenAcceptsDrift(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "managed-hooks-lifecycle-journal.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	ensured := stubWindowsManagedHooksTrust(t, managed.CanonicalBoundary, nil)

	if err := validateWindowsManagedHooksTrustedFile(path, managed.ObjectAdminFile, "lifecycle journal"); err != nil {
		t.Fatalf("residual file drift was fatal: %v", err)
	}
	if err := validateWindowsManagedHooksTrustedDir(dir, managed.ObjectStateDirectory, "state root"); err != nil {
		t.Fatalf("residual folder drift was fatal: %v", err)
	}
	if got := *ensured; len(got) != 2 || got[0] != managed.ObjectAdminFile || got[1] != managed.ObjectStateDirectory {
		t.Fatalf("EnsureCanonical calls = %v, want AdminFile then StateDirectory", got)
	}

	// No canonical form: nothing is stamped, drift is still accepted.
	*ensured = nil
	if err := validateWindowsManagedHooksTrustedFile(path, "", "transaction backup"); err != nil {
		t.Fatalf("drift on an object without a canonical form was fatal: %v", err)
	}
	if len(*ensured) != 0 {
		t.Fatalf("EnsureCanonical ran for an object without a canonical form: %v", *ensured)
	}
}

func TestWindowsManagedHooksTrustKeepsStructureAndStrictFatal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pending.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	stubWindowsManagedHooksTrust(t, managed.CanonicalStructural, errors.New("hard link count 2"))
	if err := validateWindowsManagedHooksTrustedFile(path, managed.ObjectAdminFile, "pending"); err == nil {
		t.Fatal("structural EnsureCanonical failure was accepted")
	}

	stubWindowsManagedHooksTrust(t, managed.CanonicalBoundary, nil)
	if err := validateWindowsManagedHooksTrustedFile(filepath.Join(dir, "missing.json"), "", "missing"); err == nil {
		t.Fatal("missing file was accepted")
	}
	if err := validateWindowsManagedHooksTrustedDir(path, "", "not a folder"); err == nil {
		t.Fatal("regular file accepted as a folder")
	}

	t.Setenv(managed.TrustStrictAncestorsEnv, "1")
	if err := validateWindowsManagedHooksTrustedFile(path, managed.ObjectAdminFile, "pending"); err == nil {
		t.Fatal("strict pin accepted file drift")
	}
	if err := validateWindowsManagedHooksTrustedDir(dir, managed.ObjectStateDirectory, "state root"); err == nil {
		t.Fatal("strict pin accepted folder drift")
	}
}

func TestWindowsManagedHooksObjectKindFollowsInstallLayout(t *testing.T) {
	state := `C:\ProgramData\Cisco\Cisco Secure Client\DefenseClaw`
	for path, want := range map[string]managed.ObjectKind{
		filepath.Join(state, "install", "pending.json"):                                  managed.ObjectAdminFile,
		filepath.Join(state, "install", "managed-hooks-lifecycle-journal.json"):          managed.ObjectAdminFile,
		filepath.Join(state, "hook-guardian", "targets.yaml"):                            managed.ObjectAdminFile,
		filepath.Join(state, "install", "transactions", "0123", "snapshot.json"):         "",
		`C:\Program Files\Cisco\Cisco Secure Client\DefenseClaw\defenseclaw-gateway.exe`: "",
	} {
		if got := windowsManagedHooksObjectKind(path); got != want {
			t.Errorf("windowsManagedHooksObjectKind(%q) = %q, want %q", path, got, want)
		}
	}
}
