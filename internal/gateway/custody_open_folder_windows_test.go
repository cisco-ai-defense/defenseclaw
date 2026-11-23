// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"runtime"
	"testing"

	"golang.org/x/sys/windows"
)

// custodyFolderRepairCommand is the command a custody refusal of an open
// folder prints.
const custodyFolderRepairCommand = "icacls"

// openFolderToOtherAccounts grants Everyone full control of dir itself, the
// NTFS form of mode 0757, and returns the call that restores its DACL.
func openFolderToOtherAccounts(t *testing.T, dir string) (closeFolder func()) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	old, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	open, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(everyone),
		},
	}}, old)
	if err != nil {
		t.Fatal(err)
	}
	protection := windows.SECURITY_INFORMATION(windows.UNPROTECTED_DACL_SECURITY_INFORMATION)
	if control&windows.SE_DACL_PROTECTED != 0 {
		protection = windows.PROTECTED_DACL_SECURITY_INFORMATION
	}
	set := func(dacl *windows.ACL) {
		t.Helper()
		if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|protection, nil, nil, dacl, nil); err != nil {
			t.Fatalf("set the DACL of %s: %v", dir, err)
		}
	}
	set(open)
	return func() {
		t.Helper()
		set(old)
		runtime.KeepAlive(sd)
	}
}
