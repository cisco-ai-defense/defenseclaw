// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package pathidentity

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// rel-1-0-10:GAP-1263 (CHK-RF-WINPATH-R2 Q3, P3): the hold opens a path one
// component at a time (holdByComponents) only when the whole-path open meets
// a reparse point on the way, as a cloud files placeholder folder is, and no
// box has a cloud provider, so no native row reached it. It is called here
// directly: a plain path opens to the same file, every folder above it is
// pinned while the handle is open, a junction on the way is refused before
// anything below it is looked up, and a junction at the end is opened
// itself (holdUnlinked then refuses it as a link).
func TestGAP1263HoldByComponentsOpensEachFolderUnfollowed(t *testing.T) {
	root, held := heldTree(t, "file")
	junction := filepath.Join(root, "jn")
	if out, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", junction, filepath.Join(root, "above")).CombinedOutput(); err != nil {
		t.Fatalf("junction: %v %s", err, out)
	}
	open := func(t *testing.T, path string) (windows.Handle, error) {
		t.Helper()
		nt, err := ntPathName(path)
		if err != nil {
			t.Fatal(err)
		}
		return holdByComponents(nt, holdAccesses[0], holdShare)
	}
	identity := func(t *testing.T, handle windows.Handle) windows.ByHandleFileInformation {
		t.Helper()
		var info windows.ByHandleFileInformation
		if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
			t.Fatal(err)
		}
		return info
	}
	t.Run("plain", func(t *testing.T) {
		handle, err := open(t, held)
		if err != nil {
			t.Fatalf("plain path: %v", err)
		}
		defer windows.CloseHandle(handle) //nolint:errcheck // test handle
		name, err := windows.UTF16PtrFromString(held)
		if err != nil {
			t.Fatal(err)
		}
		byName, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer windows.CloseHandle(byName) //nolint:errcheck // test handle
		got, want := identity(t, handle), identity(t, byName)
		if got.VolumeSerialNumber != want.VolumeSerialNumber || got.FileIndexHigh != want.FileIndexHigh || got.FileIndexLow != want.FileIndexLow {
			t.Fatal("the component walk opened another file than the name names")
		}
		if linked, err := handleIsLink(handle); err != nil || linked {
			t.Fatalf("plain file read as a link (%v, %v)", linked, err)
		}
		above := filepath.Join(root, "above")
		if err := os.Rename(above, above+".old"); err == nil {
			t.Fatal("a folder above the component-walk hold was renamed while it was open")
		}
	})
	t.Run("junction-on-the-way", func(t *testing.T) {
		handle, err := open(t, filepath.Join(junction, "sub", "held"))
		if err == nil {
			_ = windows.CloseHandle(handle)
		}
		if !errors.Is(err, ErrLinked) {
			t.Fatalf("a junction on the way: %v, want ErrLinked", err)
		}
	})
	t.Run("junction-at-the-end", func(t *testing.T) {
		handle, err := open(t, junction)
		if err != nil {
			t.Fatalf("a junction at the end: %v, want its own handle", err)
		}
		defer windows.CloseHandle(handle) //nolint:errcheck // test handle
		if linked, err := handleIsLink(handle); err != nil || !linked {
			t.Fatalf("the junction's own handle read as no link (%v, %v)", linked, err)
		}
	})
	t.Run("missing", func(t *testing.T) {
		handle, err := open(t, filepath.Join(root, "above", "missing"))
		if err == nil {
			_ = windows.CloseHandle(handle)
			t.Fatal("a missing name opened")
		}
	})
}
