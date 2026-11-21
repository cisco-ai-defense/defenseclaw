// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

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
	if err := os.Rename(victim, path); err != nil {
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

// TestGAP1672FolderWithoutTheGuardianShapeIsNotHealed: a SYSTEM-owned config
// the account cannot open, in an account-owned folder whose DACL is not the
// guardian setup shape (here one extra inheritable entry), is left alone.
// Fails on f36b28f9db, which never looked at the folder DACL.
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
	if err := windows.SetNamedSecurityInfo(filepath.Dir(path), windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, otherDACL, nil); err != nil {
		t.Fatalf("set a non-guardian folder DACL: %v", err)
	}
	if _, err := os.ReadFile(path); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("fixture: the account can read its LocalSystem-owned config (err %v)", err)
	}

	_ = healAtomicTransformV2ConfigLeftToAdmin(path)

	if owner := gap1651OwnerOf(t, path); owner == nil || !owner.IsWellKnown(windows.WinLocalSystemSid) {
		t.Fatalf("GAP-1672: owner after the heal in a non-guardian folder = %v; want LocalSystem kept", owner)
	}
}
