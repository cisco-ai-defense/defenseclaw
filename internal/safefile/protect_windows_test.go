// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package safefile

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestWriteWindowsRemovesInheritedUnauthorizedWriter(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "Unicode space 測試")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(everyone),
		},
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil,
	); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "state.json")
	if err := ProtectDirectory(dir); err != nil {
		t.Fatalf("protect managed directory: %v", err)
	}
	if err := Write(path, []byte(`{"fixture":"synthetic"}`)); err != nil {
		t.Fatalf("initial write: %v", err)
	}
	if err := Write(path, []byte(`{"fixture":"rewritten"}`)); err != nil {
		t.Fatalf("atomic rewrite: %v", err)
	}
	assertNoUnauthorizedWindowsWriter(t, path)
	assertNoUnauthorizedWindowsWriter(t, dir)
}

func TestWriteWindowsPreservesStricterExistingDACL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stricter.json")
	if err := Write(path, []byte("first")); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	entries := []windows.EXPLICIT_ACCESS{
		windowsAccessEntry(user.User.Sid, windows.GENERIC_ALL),
		windowsAccessEntry(system, windows.GENERIC_READ),
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil,
	); err != nil {
		t.Fatal(err)
	}
	wantSystemMask := windowsAllowMaskForSID(t, path, system)
	if err := Write(path, []byte("second")); err != nil {
		t.Fatal(err)
	}
	if got := windowsAllowMaskForSID(t, path, system); got != wantSystemMask {
		t.Fatalf("SYSTEM mask = 0x%x, want preserved 0x%x", uint32(got), uint32(wantSystemMask))
	}
}

func TestProtectDirectoryWindowsRejectsNestedJunction(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(root, "outside")
	child := filepath.Join(outside, "child")
	if err := os.MkdirAll(child, 0o700); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(root, "junction")
	if output, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", junction, outside).CombinedOutput(); err != nil {
		t.Skipf("junction creation unavailable: %v (%s)", err, output)
	}
	defer os.Remove(junction)

	if err := ProtectDirectory(filepath.Join(junction, "child")); err == nil {
		t.Fatal("ProtectDirectory accepted a nested junction escape")
	}
}

func TestWritePrivateWindowsHoldsDirectoryAgainstSwap(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "managed")
	target := filepath.Join(parent, "state.json")
	moved := filepath.Join(root, "moved")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	swapRefused := false
	err := writePrivate(target, []byte("synthetic fixture"), func() {
		if renameErr := os.Rename(parent, moved); renameErr != nil {
			swapRefused = true
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if !swapRefused {
		t.Fatal("managed directory was swappable while private write lock was held")
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("state file missing after locked write: %v", err)
	}
}

func windowsAccessEntry(sid *windows.SID, mask windows.ACCESS_MASK) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: mask,
		AccessMode:        windows.GRANT_ACCESS,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}

func windowsAllowMaskForSID(t *testing.T, path string, want *windows.SID) windows.ACCESS_MASK {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("DACL: %v", err)
	}
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			t.Fatal(err)
		}
		if ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid.Equals(want) {
			return ace.Mask
		}
	}
	return 0
}

func assertNoUnauthorizedWindowsWriter(t *testing.T, path string) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(
		path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("DACL: %v", err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	foundSystem := false
	const writeLike = windows.GENERIC_ALL | windows.GENERIC_WRITE | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES | 0x40
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			t.Fatal(err)
		}
		if ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Mask&writeLike == 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid.Equals(system) {
			foundSystem = true
			continue
		}
		if owner != nil && sid.Equals(owner) {
			continue
		}
		t.Fatalf("unauthorized writable SID %s on %s", sid.String(), path)
	}
	if !foundSystem {
		t.Fatalf("LocalSystem access missing on %s", path)
	}
}
