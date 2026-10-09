//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// GAP-0927, GAP-0929: status and verify fail on a hook runtime folder that
// standard users can write and on one they cannot read, and name the
// folder, the Users entry and the fix.
func TestWindowsEnterpriseHookRuntimeAccessFailsStatusInBothDirections(t *testing.T) {
	dir := t.TempDir()
	original := windowsEnterpriseHookRuntimeDir
	t.Cleanup(func() { windowsEnterpriseHookRuntimeDir = original })
	windowsEnterpriseHookRuntimeDir = func() (string, error) { return dir, nil }
	// setAccess writes the SDDL's DACL and, when it names one, its owner. The
	// owner matters: a new folder belongs to the test account, which is owner
	// drift on its own, so the clean case must make Administrators the owner.
	setAccess := func(sddl string) error {
		descriptor, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			return err
		}
		dacl, _, err := descriptor.DACL()
		if err != nil {
			return err
		}
		owner, _, err := descriptor.Owner()
		if err != nil {
			return err
		}
		info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
		if owner != nil {
			info |= windows.OWNER_SECURITY_INFORMATION
		}
		return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, info, owner, nil, dacl, nil)
	}
	// Let the test's own account remove the folder again.
	t.Cleanup(func() { _ = setAccess("D:P(A;OICI;FA;;;WD)") })
	for _, tc := range []struct {
		name, sddl, want string
	}{
		{"users modify", "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;BU)", "(S-1-5-32-545) holds modify (0x"},
		{"users read removed", "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", "(S-1-5-32-545) read and execute entry is missing"},
		{"users read denied", "O:BAD:P(D;OICI;0x1200a9;;;BU)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)", "(S-1-5-32-545) has an explicit deny entry"},
		{"as DefenseClaw sets it", "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := setAccess(tc.sddl); errors.Is(err, windows.ERROR_INVALID_OWNER) {
				t.Skip("making Administrators the owner needs an elevated token")
			} else if err != nil {
				t.Fatal(err)
			}
			result := enterprisestatus.New("verify", "standalone", "windows", "test")
			applyWindowsEnterpriseHookRuntimeAccess(result)
			if tc.want == "" {
				if len(result.Errors) != 0 {
					t.Fatalf("errors = %+v", result.Errors)
				}
				return
			}
			if len(result.Errors) != 1 || result.Errors[0].Code != "machine_policy_summary_untrusted" ||
				!strings.Contains(result.Errors[0].Message, dir) || !strings.Contains(result.Errors[0].Message, tc.want) ||
				!strings.Contains(result.Errors[0].Message, "*S-1-5-32-545:(OI)(CI)RX") {
				t.Fatalf("errors = %+v", result.Errors)
			}
			if tc.name == "users read denied" {
				originalRepair := windowsEnterpriseRepairPublicDir
				t.Cleanup(func() { windowsEnterpriseRepairPublicDir = originalRepair })
				called := false
				windowsEnterpriseRepairPublicDir = func(path string) error {
					called = path == dir
					return nil
				}
				if repairWindowsEnterpriseHookRuntimeAccess() == "" || !called {
					t.Fatal("repair did not restore the drifted hook runtime directory")
				}
			}
		})
	}
}
