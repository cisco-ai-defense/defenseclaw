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

// The teardown journal has no protected digest, so drift is repaired and the
// strict check must then pass: residual owner/writer drift stays fatal.
func TestWindowsManagedHooksTeardownJournalRequiresStrictAfterRepair(t *testing.T) {
	t.Setenv(managed.TrustStrictAncestorsEnv, "")
	path := filepath.Join(t.TempDir(), windowsManagedHooksTeardownJournalFile)
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	ensured := stubWindowsManagedHooksTrust(t, managed.CanonicalBoundary, nil)
	if err := validateWindowsManagedHooksTeardownJournalFile(path); err == nil {
		t.Fatal("residual teardown journal drift was accepted")
	}
	if got := *ensured; len(got) != 1 || got[0] != managed.ObjectAdminFile {
		t.Fatalf("EnsureCanonical calls = %v, want one AdminFile repair", got)
	}
	if _, err := readWindowsManagedHooksTeardownJournal(path); err == nil {
		t.Fatal("teardown journal with residual drift was read")
	}

	// The repair clears the drift: the strict re-check passes.
	stubWindowsManagedHooksTrust(t, managed.CanonicalRepaired, nil)
	repaired := false
	windowsManagedHooksEnsureCanonical = func(p string, kind managed.ObjectKind, _ managed.CanonicalOptions) (managed.CanonicalResult, error) {
		repaired = true
		return managed.CanonicalResult{Path: p, Kind: kind, Outcome: managed.CanonicalRepaired}, nil
	}
	windowsManagedHooksStrictFileCheck = func(string, string) error {
		if repaired {
			return nil
		}
		return errors.New("owner S-1-5-21-1-2-3-1001 is not trusted")
	}
	if err := validateWindowsManagedHooksTeardownJournalFile(path); err != nil {
		t.Fatalf("repaired teardown journal was refused: %v", err)
	}

	t.Setenv(managed.TrustStrictAncestorsEnv, "1")
	repaired = false
	if err := validateWindowsManagedHooksTeardownJournalFile(path); err == nil || repaired {
		t.Fatalf("strict pin: err = %v, repaired = %v; want the strict refusal without repair", err, repaired)
	}
}

// The reader parses bytes from the handle that was validated, and refuses a
// journal that is not a single-link regular file.
func TestReadWindowsManagedHooksTeardownJournalReadsValidatedHandle(t *testing.T) {
	t.Setenv(managed.TrustStrictAncestorsEnv, "")
	dir := t.TempDir()
	path := filepath.Join(dir, windowsManagedHooksTeardownJournalFile)
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	originalFile := windowsManagedHooksStrictFileCheck
	t.Cleanup(func() { windowsManagedHooksStrictFileCheck = originalFile })
	validated := 0
	windowsManagedHooksStrictFileCheck = func(string, string) error {
		validated++
		return nil
	}
	// "{}" passes validation and reaches the schema layer through the handle.
	if _, err := readWindowsManagedHooksTeardownJournal(path); err == nil ||
		err.Error() != "managed-hook teardown journal is missing manifest_sha256" {
		t.Fatalf("read error = %v, want the schema refusal", err)
	}
	if validated != 1 {
		t.Fatalf("strict check ran %d times, want 1", validated)
	}

	if err := os.Link(path, filepath.Join(dir, "second-link.json")); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	if _, err := readWindowsManagedHooksTeardownJournal(path); err == nil {
		t.Fatal("hard-linked teardown journal was read")
	}
}
