//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// GAP-0935: the guardian keeps a copy of the recorded hook binary and puts a
// missing (quarantined) binary back from it; a copy of another release is
// never restored.
func TestKeepWindowsManagedFileCopyRestoresAMissingHookBinary(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "bin", "defenseclaw-hook.exe")
	copyPath := filepath.Join(root, "hook-guardian", "payload", "defenseclaw-hook.exe")
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("hook release"), 0o600); err != nil {
		t.Fatal(err)
	}
	want, err := windowsFileSHA256Hex(target)
	if err != nil {
		t.Fatal(err)
	}
	if restored, err := keepWindowsManagedFileCopy(target, copyPath, want); err != nil || restored {
		t.Fatalf("keep copy: restored %t, %v", restored, err)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if restored, err := keepWindowsManagedFileCopy(target, copyPath, want); err != nil || !restored {
		t.Fatalf("restore: restored %t, %v", restored, err)
	}
	if body, err := os.ReadFile(target); err != nil || string(body) != "hook release" {
		t.Fatalf("restored %q, %v", body, err)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if restored, err := keepWindowsManagedFileCopy(target, copyPath, "0000"); err == nil || restored {
		t.Fatalf("a copy of another release was restored: %t, %v", restored, err)
	}
}

// GAP-0934, GAP-0937: the copy an upgrade kept of the ACP guard an editor
// still ran goes as soon as nothing runs it; other files stay.
func TestRemoveWindowsReplacementCopiesRemovesOnlyUnusedCopies(t *testing.T) {
	dir := t.TempDir()
	unused := filepath.Join(dir, "defenseclaw-acp.exe.backup.b93b18a784c74be1bdd7803057d577bd")
	held := filepath.Join(dir, "defenseclaw-hook.exe.backup.d9a400178cdb4634a2599baba406ffd5")
	other := filepath.Join(dir, "defenseclaw-acp.exe.backup.notacopy")
	for _, path := range []string{unused, held, other} {
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A running program holds its image open without delete sharing.
	name, err := windows.UTF16PtrFromString(held)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(handle)
	removed := removeWindowsReplacementCopies(dir)
	if len(removed) != 1 || removed[0] != unused {
		t.Fatalf("removed %q", removed)
	}
	for _, path := range []string{held, other} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}
}
