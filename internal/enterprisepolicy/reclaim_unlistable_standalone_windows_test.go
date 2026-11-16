//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// g582 review 4 F1: a vendor folder holding a DefenseClaw file whose
// descriptor and listing are hidden from SYSTEM and Administrators (an OWNER
// RIGHTS entry with only FILE_READ_ATTRIBUTES, SYNCHRONIZE and WRITE_DAC) made the
// standalone refusal see no DefenseClaw file, so the folder was taken over in
// place. An unlistable folder now counts as holding one.
func TestWindowsReclaimRefusesAnUnlistableFolderOnStandalone(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated token (the Windows CI runners and the native test hosts run elevated)")
	}
	for _, via := range []string{"reconcile", "setup repair"} {
		t.Run(via, func(t *testing.T) {
			opts := windowsTestOptions(t)
			github := filepath.Join(opts.WindowsProgramData, "GitHub")
			copilot := filepath.Join(github, "Copilot")
			for _, dir := range []string{github, copilot} {
				if err := createProtectedDir(dir); err != nil {
					t.Fatal(err)
				}
			}
			dir := filepath.Join(copilot, "policy.d")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "50-defenseclaw.json"), []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
			disableBackupPrivilegesForTest(t)
			stampF1(t, dir, "O:BAG:SYD:P(A;OICI;0x140080;;;OW)(A;OICI;FA;;;BG)")
			t.Cleanup(func() { stampF1(t, dir, "O:BAG:SYD:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)") })
			if _, err := os.ReadDir(dir); err == nil {
				t.Skip("this token still lists the folder")
			}
			previous := reclaimRefusesContentDrift
			reclaimRefusesContentDrift = func() bool { return true }
			t.Cleanup(func() { reclaimRefusesContentDrift = previous })

			var err error
			if via == "reconcile" {
				_, err = reclaimPolicyDirs(opts, dir)
			} else {
				err = RepairWindowsPublicDir(dir)
			}

			var refused *managed.StandaloneContentDriftError
			if !errors.As(err, &refused) {
				t.Fatalf("err = %v, want a standalone refusal", err)
			}
			if _, listErr := os.ReadDir(dir); listErr == nil {
				t.Fatal("the unlistable folder was taken over in place")
			}
		})
	}
}

func stampF1(t *testing.T, path, sddl string) {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, _ := descriptor.Owner()
	group, _, _ := descriptor.Group()
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	extended, err := winpath.Extended(path)
	if err != nil {
		t.Fatal(err)
	}
	info := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION | windows.GROUP_SECURITY_INFORMATION |
		windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if err := managed.RunWithWindowsRepairPrivileges(func() error {
		return windows.SetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, info, owner, group, dacl, nil)
	}); err != nil {
		t.Fatalf("stamp %s on %s: %v", sddl, path, err)
	}
}

// disableBackupPrivilegesForTest disables SeBackupPrivilege and
// SeRestorePrivilege on the process token for the test, as on an elevated
// prompt (an elevated SSH or SYSTEM token has them enabled, and backup
// semantics then read any descriptor). The repair privileges helpers still
// enable them on their own impersonation thread.
func disableBackupPrivilegesForTest(t *testing.T) {
	t.Helper()
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = token.Close() })
	for _, name := range []string{"SeBackupPrivilege", "SeRestorePrivilege"} {
		var luid windows.LUID
		if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(name), &luid); err != nil {
			t.Fatal(err)
		}
		state := windows.Tokenprivileges{PrivilegeCount: 1, Privileges: [1]windows.LUIDAndAttributes{{Luid: luid}}}
		var previous windows.Tokenprivileges
		var size uint32
		if err := windows.AdjustTokenPrivileges(token, false, &state, uint32(unsafe.Sizeof(previous)), &previous, &size); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if previous.PrivilegeCount > 0 {
				_ = windows.AdjustTokenPrivileges(token, false, &previous, 0, nil, nil)
			}
		})
	}
}
