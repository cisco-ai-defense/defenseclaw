// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// GAP-2065: a marker that another account owns is not a marker. Setting a
// foreign owner needs SeRestorePrivilege; the test enables it for its own
// duration and skips when the token does not hold it.
func TestNativeOTLPTakeBackPendingMarkerOwnedByAnotherAccountIsNotRead(t *testing.T) {
	dataDir := t.TempDir()
	if err := RecordNativeOTLPTakeBackPending(dataDir, "codex"); err != nil {
		t.Fatal(err)
	}
	if !NativeOTLPTakeBackPending(dataDir, "codex") {
		t.Fatal("a marker this account wrote is not pending")
	}
	foreign, err := windows.CreateWellKnownSid(windows.WinLocalServiceSid)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dataDir, "native-otlp-take-back-pending-codex.json")
	restore := enableNativeOTLPTestPrivilege(t, "SeRestorePrivilege")
	err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, foreign, nil, nil, nil)
	restore()
	if err != nil {
		t.Skipf("cannot give the marker a foreign owner on this host: %v", err)
	}
	if NativeOTLPTakeBackPending(dataDir, "codex") {
		t.Fatal("a marker owned by LOCAL SERVICE in the account's data directory was read as pending")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}

func enableNativeOTLPTestPrivilege(t *testing.T, name string) func() {
	t.Helper()
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		return func() {}
	}
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(name), &luid); err != nil {
		token.Close()
		return func() {}
	}
	set := func(attributes uint32) {
		privileges := windows.Tokenprivileges{PrivilegeCount: 1}
		privileges.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: attributes}
		_ = windows.AdjustTokenPrivileges(token, false, &privileges, uint32(unsafe.Sizeof(privileges)), nil, nil)
	}
	set(windows.SE_PRIVILEGE_ENABLED)
	return func() {
		set(0)
		token.Close()
	}
}
