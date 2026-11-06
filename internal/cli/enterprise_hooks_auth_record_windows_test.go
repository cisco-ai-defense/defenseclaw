//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// g582 review 5 L3: the standalone folder-record decision trusts the hook
// guardian ledger only through managed.WindowsAdminOnlyRecord, and the rows
// that prove it stamp the ledger with a fixture descriptor. This row stamps
// one with the ownership the guardian really gives it
// (setEnterpriseHookAuthorizationOwnership: Administrators owner, the
// gateway service's read entry) and requires it to count as an
// administrator record; the twin a standard user can change does not.
func TestGuardianLedgerWithTheRealOwnershipIsAnAdministratorRecord(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated administrator or SYSTEM")
	}
	// A service account that exists on every Windows host stands in for the
	// gateway's, as the secret rows do.
	t.Setenv(managed.WindowsServiceAccountEnv, `NT SERVICE\W32Time`)
	path := filepath.Join(t.TempDir(), "protected_targets.json")
	if err := os.WriteFile(path, []byte("{\"targets\":[]}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := setEnterpriseHookAuthorizationOwnership(path); err != nil {
		t.Fatalf("stamp the ledger: %v", err)
	}
	if !managed.WindowsAdminOnlyRecord(path) {
		sd, _ := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		t.Fatalf("a ledger with the guardian's own ownership is not an administrator record: %v", sd)
	}
	if out, err := exec.Command("icacls.exe", path, "/grant", "*S-1-5-32-545:(M)").CombinedOutput(); err != nil {
		t.Fatalf("grant Users modify: %v\n%s", err, out)
	}
	if managed.WindowsAdminOnlyRecord(path) {
		t.Fatal("a ledger a standard user can change counts as an administrator record")
	}
}
