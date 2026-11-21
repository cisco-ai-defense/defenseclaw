// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// gap1651OwnerOf reads the owner of path with the repair privileges, so a
// SYSTEM-only object can still be inspected.
func gap1651OwnerOf(t *testing.T, path string) *windows.SID {
	t.Helper()
	var owner *windows.SID
	if err := runWindowsManagedPrivilegedRepair(func() error {
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
	}); err != nil {
		t.Fatalf("read owner of %s: %v", path, err)
	}
	return owner
}

// gap1651SystemOnlyVictim makes <root>\.codex\config.toml owned by
// LocalSystem with a protected SYSTEM and Administrators DACL: a stand-in for
// a SYSTEM-only file (machine policy, token) the account must never be given.
func gap1651SystemOnlyVictim(t *testing.T) (root, file string) {
	t.Helper()
	root = t.TempDir()
	dir := filepath.Join(root, ".codex")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	file = filepath.Join(dir, "config.toml")
	if err := os.WriteFile(file, []byte("secret = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	private, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)")
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
		return windows.SetNamedSecurityInfo(file, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
			system, nil, privateDACL, nil)
	}); err != nil {
		t.Fatalf("make the victim SYSTEM-only: %v", err)
	}
	if owner := gap1651OwnerOf(t, file); owner == nil || !owner.IsWellKnown(windows.WinLocalSystemSid) {
		t.Fatalf("victim owner = %v, want LocalSystem", owner)
	}
	return root, file
}

// TestGAP1651SwapBetweenFolderCheckAndFileOpenHandsNothingOver swaps the
// account's folder, or an ancestor of it, for a junction to a SYSTEM-only
// file's folder in the window after the heal checked the folder owner and
// before it opened the config. The heal must never hand that file over.
func TestGAP1651SwapBetweenFolderCheckAndFileOpenHandsNothingOver(t *testing.T) {
	for _, tc := range []struct {
		name string
		// pinned: the heal holds this folder without delete sharing, so
		// the rename itself must be refused.
		pinned bool
		// swapped returns the path to move away and the victim folder the
		// junction left in its place points at.
		swapped func(codexDir, victimRoot string) (from, target string)
	}{
		{"folder", true, func(codexDir, victimRoot string) (string, string) {
			return codexDir, filepath.Join(victimRoot, ".codex")
		}},
		{"ancestor", false, func(codexDir, victimRoot string) (string, string) {
			return filepath.Dir(codexDir), victimRoot
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, _, user := gap1651Fixture(t, nil)
			victimRoot, victim := gap1651SystemOnlyVictim(t)
			from, target := tc.swapped(filepath.Dir(path), victimRoot)
			moved := from + "-moved"
			var renameErr, junctionErr error
			var junctionOut []byte
			ran := 0
			atomicTransformV2OwnerHealBeforeFileOpen = func() {
				ran++
				if renameErr = os.Rename(from, moved); renameErr != nil {
					return
				}
				junctionOut, junctionErr = exec.Command("cmd.exe", "/D", "/C", "mklink", "/J", from, target).CombinedOutput()
			}
			t.Cleanup(func() {
				atomicTransformV2OwnerHealBeforeFileOpen = nil
				if renameErr == nil && ran > 0 {
					// Removes only the junction, never its target.
					_ = os.Remove(from)
					_ = os.Rename(moved, from)
				}
			})

			healErr := healAtomicTransformV2ConfigLeftToAdmin(path)
			if ran != 1 {
				t.Fatalf("swap hook ran %d times, want 1 (heal err %v)", ran, healErr)
			}
			if renameErr == nil && junctionErr != nil {
				t.Fatalf("swap: junction %s -> %s: %v\n%s", from, target, junctionErr, junctionOut)
			}
			t.Logf("swap rename of %s: %v; heal: %v", from, renameErr, healErr)
			if tc.pinned && renameErr == nil {
				t.Errorf("the folder was renamed while the heal held it; want the rename refused")
			}
			if owner := gap1651OwnerOf(t, victim); owner == nil || !owner.IsWellKnown(windows.WinLocalSystemSid) {
				t.Fatalf("GAP-1651 TOCTOU: a %s swap after the folder check handed the SYSTEM-only file %s to the account (owner now %v)",
					tc.name, victim, owner)
			}
			real := path
			if renameErr == nil {
				real = filepath.Join(moved, gap1651Rel(t, from, path))
			}
			if owner := gap1651OwnerOf(t, real); owner == nil || !owner.Equals(user) {
				t.Fatalf("the account's own config %s was not given back (owner %v, heal err %v)", real, owner, healErr)
			}
		})
	}
}

func gap1651Rel(t *testing.T, base, target string) string {
	t.Helper()
	rel, err := filepath.Rel(base, target)
	if err != nil {
		t.Fatal(err)
	}
	return rel
}
