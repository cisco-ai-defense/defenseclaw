//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// g582 review 3 (class audit E1): the guardian's ledger repair, which runs
// before every read of the authorization roster, re-stamped a ledger file
// another account could write, so the next read trusted a roster that
// account may have edited. On standalone it is refused and named; a
// trusted-only drift and Secure Client keep the repair.
func TestEnterpriseHookGuardianLedgerStandaloneNeverRestampsAnUntrustedWriter(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated token")
	}
	for _, tc := range []struct {
		name       string
		sddl       string
		standalone bool
		refused    bool
	}{
		{name: "Users Modify on the roster", sddl: "O:BAG:SYD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;0x1301bf;;;BU)", standalone: true, refused: true},
		{name: "Users owner of the roster", sddl: "O:BUG:SYD:P(A;;FA;;;BA)(A;;FA;;;SY)", standalone: true, refused: true},
		{name: "twin: trusted-only drift is repaired", sddl: "O:BAG:SYD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FR;;;BU)", standalone: true},
		{name: "twin: Secure Client is repaired", sddl: "O:BAG:SYD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;0x1301bf;;;BU)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := t.TempDir()
			roster := filepath.Join(managed.HookGuardianAuthorizationDir(dataDir), hookGuardianAuthorizationFile)
			if err := os.MkdirAll(filepath.Dir(roster), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(roster, []byte(`{"targets":[]}`), 0o600); err != nil {
				t.Fatal(err)
			}
			setLedgerTestSDDL(t, roster, tc.sddl)
			drifted := map[string]bool{roster: true}
			repaired, _ := stubEnterpriseHookGuardianLedger(t, drifted, nil)
			previous := enterpriseHookGuardianLedgerRefusesContentDrift
			previousRefusal := enterpriseHookGuardianLedgerStandaloneRefusal
			enterpriseHookGuardianLedgerRefusesContentDrift = func() bool { return tc.standalone }
			enterpriseHookGuardianLedgerStandaloneRefusal = enterpriseHookGuardianLedgerStandaloneRefusalPlatform
			t.Cleanup(func() {
				enterpriseHookGuardianLedgerRefusesContentDrift = previous
				enterpriseHookGuardianLedgerStandaloneRefusal = previousRefusal
			})

			err := repairEnterpriseHookGuardianLedger(dataDir)

			if tc.refused {
				var refused *managed.StandaloneContentDriftError
				if len(*repaired) != 0 || !errors.As(err, &refused) || !strings.Contains(err.Error(), roster) {
					t.Fatalf("repaired=%v err=%v, want the roster refused and not re-stamped", *repaired, err)
				}
				return
			}
			if err != nil || len(*repaired) != 1 || (*repaired)[0] != roster {
				t.Fatalf("repaired=%v err=%v, want the roster repaired", *repaired, err)
			}
		})
	}
}

func setLedgerTestSDDL(t *testing.T, path, sddl string) {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	extended, err := winpath.Extended(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := enterprisehooks.RunWithWindowsOwnerRestorePrivilege(func() error {
		return windows.SetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
			owner, nil, dacl, nil)
	}); err != nil {
		t.Fatal(err)
	}
}
