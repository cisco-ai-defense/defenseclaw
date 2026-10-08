//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
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
	setDACL := func(sddl string) error {
		descriptor, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			return err
		}
		dacl, _, err := descriptor.DACL()
		if err != nil {
			return err
		}
		return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
	}
	// Let the test's own account remove the folder again.
	t.Cleanup(func() { _ = setDACL("D:P(A;OICI;FA;;;WD)") })
	for _, tc := range []struct {
		name, sddl, want string
	}{
		{"users modify", "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;BU)", "(S-1-5-32-545) holds modify (0x"},
		{"users read removed", "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", "(S-1-5-32-545) read and execute entry is missing"},
		{"as DefenseClaw sets it", "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := setDACL(tc.sddl); err != nil {
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
		})
	}
}
