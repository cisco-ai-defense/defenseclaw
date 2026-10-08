// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package ideplugins

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/sys/windows"
)

// A managed gateway reads a Kiro extensions folder without the right to stat
// the .kiro folder above it, which the guardian keeps at its exact DACL, nor
// to list the profile (GAP-0897). The installation is still found.
func TestScanFindsAnInstallationBelowAFolderItCannotStat(t *testing.T) {
	home := t.TempDir()
	kiro := filepath.Join(home, ".kiro")
	if err := os.MkdirAll(filepath.Join(kiro, "extensions", "acme.tool-1.0.0"), 0o755); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	setACE := func(path string, mode windows.ACCESS_MODE, mask windows.ACCESS_MASK) {
		t.Helper()
		sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		existing, _, err := sd.DACL()
		if err != nil {
			t.Fatal(err)
		}
		acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
			AccessPermissions: mask, AccessMode: mode, Inheritance: windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(user.User.Sid)},
		}}, existing)
		if err != nil {
			t.Fatal(err)
		}
		if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
			t.Fatal(err)
		}
	}
	setACE(home, windows.DENY_ACCESS, windows.FILE_LIST_DIRECTORY)
	setACE(kiro, windows.DENY_ACCESS, windows.FILE_READ_ATTRIBUTES)
	t.Cleanup(func() {
		setACE(kiro, windows.REVOKE_ACCESS, 0)
		setACE(home, windows.REVOKE_ACCESS, 0)
	})
	// Scan as the same account without its backup and restore privileges,
	// which an elevated administrator holds and the gateway service does not.
	runtime.LockOSThread()
	defer func() {
		_ = windows.RevertToSelf()
		runtime.UnlockOSThread()
	}()
	impersonateWithoutPrivileges(t)
	if _, err := os.Lstat(kiro); !os.IsPermission(err) {
		t.Fatalf("test setup: the folder is still readable (%v)", err)
	}
	found := false
	for _, inst := range Scan(home, "windows", Limits{}) {
		found = found || inst.Product == "kiro"
	}
	if err := windows.RevertToSelf(); err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("the Kiro installation below an unreadable .kiro was not found")
	}
}

// impersonateWithoutPrivileges makes the calling thread, which the caller
// locks and reverts, run as the process account without the privileges that
// skip file access checks.
func impersonateWithoutPrivileges(t *testing.T) {
	t.Helper()
	var process windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY, &process); err != nil {
		t.Fatal(err)
	}
	defer process.Close()
	var token windows.Token
	if err := windows.DuplicateTokenEx(process, windows.TOKEN_ALL_ACCESS, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &token); err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	for _, name := range []string{"SeBackupPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege", "SeSecurityPrivilege"} {
		var luid windows.LUID
		if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(name), &luid); err != nil {
			t.Fatal(err)
		}
		privileges := windows.Tokenprivileges{PrivilegeCount: 1, Privileges: [1]windows.LUIDAndAttributes{{Luid: luid}}}
		if err := windows.AdjustTokenPrivileges(token, false, &privileges, 0, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := windows.SetThreadToken(nil, token); err != nil {
		t.Fatal(err)
	}
}
