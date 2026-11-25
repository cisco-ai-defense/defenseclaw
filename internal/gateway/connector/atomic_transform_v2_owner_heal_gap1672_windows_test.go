// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/windows"
)

// gap1672FileRenameInformation is FILE_RENAME_INFORMATION.
type gap1672FileRenameInformation struct {
	ReplaceIfExists uint32
	RootDirectory   windows.Handle
	FileNameLength  uint32
	FileName        [1]uint16
}

// gap1672RenameWithDeleteOnly renames from to to through a handle opened with
// DELETE alone, the one right a folder's FILE_DELETE_CHILD gives on a file
// whose own DACL grants the caller nothing. os.Rename (MoveFileEx) also asks
// for SYNCHRONIZE, which only the file's DACL can grant, so it is refused;
// NtSetInformationFile on this handle is what an account would use.
func gap1672RenameWithDeleteOnly(from, to string) error {
	name, err := windows.NewNTUnicodeString(`\??\` + from)
	if err != nil {
		return err
	}
	attributes := windows.OBJECT_ATTRIBUTES{
		Length:     uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		ObjectName: name,
		Attributes: windows.OBJ_CASE_INSENSITIVE,
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	if err := windows.NtCreateFile(&handle, windows.DELETE, &attributes, &status, nil, 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, windows.FILE_OPEN,
		windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT, 0, 0); err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	target, err := windows.UTF16FromString(`\??\` + to)
	if err != nil {
		return err
	}
	length := (len(target) - 1) * 2
	var shape gap1672FileRenameInformation
	buffer := make([]byte, int(unsafe.Offsetof(shape.FileName))+length+2)
	info := (*gap1672FileRenameInformation)(unsafe.Pointer(&buffer[0]))
	info.FileNameLength = uint32(length)
	copy(unsafe.Slice(&info.FileName[0], len(target)), target)
	return windows.NtSetInformationFile(handle, &status, &buffer[0], uint32(len(buffer)), windows.FileRenameInformation)
}

// TestGAP1672SystemOnlyFileRenamedIntoTheSlotStaysSystemOwned: the account
// owns its guardian-shaped .codex folder, so it can rename into the config
// slot a SYSTEM-only file from another folder it can delete children of. The
// heal must not give that file to the account: it was not created in the
// folder (its protected DACL has no ACE inherited from it). Fails on
// f36b28f9db: the heal checked only the owners and handed the file over.
func TestGAP1672SystemOnlyFileRenamedIntoTheSlotStaysSystemOwned(t *testing.T) {
	path, _, _ := gap1651Fixture(t, nil)
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove the fixture config (the account owns the folder): %v", err)
	}
	victim := filepath.Join(t.TempDir(), "machine-secret.toml")
	if err := os.WriteFile(victim, []byte("secret = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	private, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)")
	if err != nil {
		t.Fatal(err)
	}
	privateDACL, _, err := private.DACL()
	if err != nil {
		t.Fatal(err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	if err := runWindowsManagedPrivilegedRepair(func() error {
		return windows.SetNamedSecurityInfo(victim, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
			system, nil, privateDACL, nil)
	}); err != nil {
		t.Fatalf("make the victim SYSTEM-only: %v", err)
	}
	// The rename needs only delete-child on the victim's folder and add-file
	// on the account's own folder, both of which the account has.
	if err := gap1672RenameWithDeleteOnly(victim, path); err != nil {
		t.Fatalf("rename the SYSTEM-only file into the config slot: %v", err)
	}
	if _, err := os.ReadFile(path); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("fixture: the account can read the SYSTEM-only file (err %v); the repro needs Access is denied", err)
	}

	_ = healAtomicTransformV2ConfigLeftToAdmin(path)

	if owner := gap1651OwnerOf(t, path); owner == nil || !owner.IsWellKnown(windows.WinLocalSystemSid) {
		t.Fatalf("GAP-1672: owner of the renamed SYSTEM-only file = %v after the heal; want LocalSystem kept", owner)
	}
	if _, err := os.ReadFile(path); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("GAP-1672: the account can read the renamed SYSTEM-only file after the heal (err %v)", err)
	}
}

// gap1672FileDACLOf reads the DACL of a file the account has no access to,
// with the backup privilege (READ_CONTROL by backup semantics), as
// gap1651OwnerOf reads its owner.
func gap1672FileDACLOf(t *testing.T, path string) *windows.SECURITY_DESCRIPTOR {
	t.Helper()
	var sd *windows.SECURITY_DESCRIPTOR
	if err := runWindowsManagedPrivilegedRepair(func() error {
		handle, err := openWindowsManagedRepairHandle(path, false, windows.READ_CONTROL)
		if err != nil {
			return err
		}
		defer windows.CloseHandle(handle)
		sd, err = windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		return err
	}); err != nil {
		t.Fatalf("read the DACL of %s: %v", path, err)
	}
	return sd
}

// TestGAP1672FolderWithoutTheGuardianShapeIsNotHealed: a SYSTEM-owned config
// the account cannot open, in an account-owned folder whose DACL is not the
// guardian setup shape (here one extra inheritable entry, which the file
// inherits), is left alone: the file DACL is not the two inherited ACEs of
// the setup shape. Fails on f36b28f9db, which never looked at the DACLs.
// Since GAP-1759 the heal judges only the file DACL (the folder's current
// DACL is the account's to set); this case still refuses through it.
func TestGAP1672FolderWithoutTheGuardianShapeIsNotHealed(t *testing.T) {
	path, _, _ := gap1651Fixture(t, nil)
	other, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;OW)(A;OICI;0x1200a9;;;BG)")
	if err != nil {
		t.Fatal(err)
	}
	otherDACL, _, err := other.DACL()
	if err != nil {
		t.Fatal(err)
	}
	// The config is LocalSystem-owned with no entry for the account, so the
	// new entries reach it, and its DACL is read, only with the backup and
	// restore privileges of the elevated administrator.
	if err := runWindowsManagedPrivilegedRepair(func() error {
		return windows.SetNamedSecurityInfo(filepath.Dir(path), windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
			nil, nil, otherDACL, nil)
	}); err != nil {
		t.Fatalf("set a non-guardian folder DACL: %v", err)
	}
	if made, err := managed.IsWindowsSetupRelaxedChildFileDACL(gap1672FileDACLOf(t, path)); err != nil || made {
		t.Fatalf("fixture: the config did not inherit the extra entry (setup child shape %v, err %v)", made, err)
	}
	if _, err := os.ReadFile(path); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("fixture: the account can read its LocalSystem-owned config (err %v)", err)
	}

	_ = healAtomicTransformV2ConfigLeftToAdmin(path)

	if owner := gap1651OwnerOf(t, path); owner == nil || !owner.IsWellKnown(windows.WinLocalSystemSid) {
		t.Fatalf("GAP-1672: owner after the heal in a non-guardian folder = %v; want LocalSystem kept", owner)
	}
}
