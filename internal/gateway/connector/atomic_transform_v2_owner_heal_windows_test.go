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

// gap1651Fixture builds the dc-ent-win dcw-std1 shape: a .codex folder owned
// by the account with the guardian's setup DACL (SYSTEM and OWNER RIGHTS full
// control, protected) and a config.toml in it owned by LocalSystem, so the
// account has no access to its own config.
func gap1651Fixture(t *testing.T, folderOwner *windows.SID) (path, stateDir string, user *windows.SID) {
	t.Helper()
	user, err := defaultWindowsEffectiveUserSID()
	if err != nil {
		t.Fatal(err)
	}
	if !windows.GetCurrentProcessToken().IsElevated() || user.IsWellKnown(windows.WinLocalSystemSid) {
		t.Skip("GAP-1651: run elevated as an ordinary administrator account (sets a LocalSystem owner)")
	}
	root := t.TempDir()
	dir := filepath.Join(root, "profile", ".codex")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte("model = \"gpt\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	if folderOwner == nil {
		folderOwner = user
	}
	setOwner := func(p string, owner *windows.SID, directory bool) {
		t.Helper()
		name, err := windows.UTF16PtrFromString(p)
		if err != nil {
			t.Fatal(err)
		}
		flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
		if directory {
			flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
		}
		handle, err := windows.CreateFile(name, windows.READ_CONTROL|windows.WRITE_OWNER,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
			windows.OPEN_EXISTING, flags, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer windows.CloseHandle(handle)
		sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.GROUP_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		group, _, err := sd.Group()
		if err != nil || group == nil {
			t.Fatalf("read group of %s: %v", p, err)
		}
		if err := setAtomicTransformV2PriorOwnerGroup(handle, owner, group); err != nil {
			t.Fatalf("set owner of %s: %v", p, err)
		}
	}
	// File first (owner and inherited DACL), then the folder shape.
	setOwner(path, system, false)
	setOwner(dir, folderOwner, true)
	relaxed, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;OW)")
	if err != nil {
		t.Fatal(err)
	}
	relaxedDACL, _, err := relaxed.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, relaxedDACL, nil); err != nil {
		t.Fatalf("set the guardian setup DACL on %s: %v", dir, err)
	}
	if _, err := os.ReadFile(path); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("fixture: the account can still read its LocalSystem-owned config (err %v); the repro needs Access is denied", err)
	}
	t.Cleanup(func() {
		// Let t.TempDir remove the tree.
		open, _ := windows.SecurityDescriptorFromString("D:(A;OICI;FA;;;WD)")
		openDACL, _, _ := open.DACL()
		_ = runWindowsManagedPrivilegedRepair(func() error {
			for _, p := range []string{dir, path} {
				_ = windows.SetNamedSecurityInfo(p, windows.SE_FILE_OBJECT,
					windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION,
					user, nil, openDACL, nil)
			}
			return nil
		})
	})
	return path, filepath.Join(root, "state"), user
}

func TestGAP1651ConfigOwnedBySystemInTheAccountsFolderIsGivenBack(t *testing.T) {
	path, stateDir, user := gap1651Fixture(t, nil)
	err := atomicTransformFileWithStateDir(path, stateDir, 0o600, func(data []byte, exists bool) (atomicTransformResult, error) {
		if !exists {
			t.Fatalf("config not seen as existing")
		}
		return atomicTransformResult{Data: append(append([]byte(nil), data...), []byte("[model_providers.dc]\n")...)}, nil
	})
	if err != nil {
		t.Fatalf("GAP-1651: route-only style edit of a LocalSystem-owned config in the account's own folder failed: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "model = \"gpt\"\n[model_providers.dc]\n" {
		t.Fatalf("config after edit = %q, %v", got, err)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !owner.Equals(user) {
		t.Fatalf("config owner after edit = %v, %v; want the account %s", owner, err, user)
	}
}

func TestGAP1651ConfigInAFolderTheAccountDoesNotOwnIsNotHandedOver(t *testing.T) {
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	path, stateDir, _ := gap1651Fixture(t, system)
	err = atomicTransformFileWithStateDir(path, stateDir, 0o600, func(data []byte, _ bool) (atomicTransformResult, error) {
		return atomicTransformResult{Data: []byte("x = 1\n")}, nil
	})
	if err == nil {
		t.Fatalf("edit succeeded in a LocalSystem-owned folder; the config must not be handed over")
	}
	var owner *windows.SID
	if repairErr := runWindowsManagedPrivilegedRepair(func() error {
		handle, err := openWindowsManagedRepairHandle(path, false, windows.READ_CONTROL)
		if err != nil {
			return err
		}
		defer windows.CloseHandle(handle)
		sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
		if err != nil {
			return err
		}
		owner, _, err = sd.Owner()
		return err
	}); repairErr != nil {
		t.Fatal(repairErr)
	}
	if owner == nil || !owner.IsWellKnown(windows.WinLocalSystemSid) {
		t.Fatalf("config owner = %v; want LocalSystem kept", owner)
	}
}
