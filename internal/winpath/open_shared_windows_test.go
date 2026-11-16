// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package winpath

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procReplaceFileW = windows.NewLazySystemDLL("kernel32.dll").NewProc("ReplaceFileW")

// replaceFileLikeSetup replaces path with replacement as the published
// standalone Setup does: [IO.File]::Replace, which calls ReplaceFileW with
// merge and access-list errors ignored, keeping the old file at backup.
func replaceFileLikeSetup(replacement, path, backup string) error {
	const ignoreMergeErrors, ignoreACLErrors = 0x2, 0x4
	names := make([]*uint16, 3)
	for i, name := range []string{path, replacement, backup} {
		pointer, err := windows.UTF16PtrFromString(name)
		if err != nil {
			return err
		}
		names[i] = pointer
	}
	ok, _, err := procReplaceFileW.Call(uintptr(unsafe.Pointer(names[0])), uintptr(unsafe.Pointer(names[1])),
		uintptr(unsafe.Pointer(names[2])), ignoreMergeErrors|ignoreACLErrors, 0, 0)
	if ok == 0 {
		return err
	}
	return nil
}

// GAP-0200: Setup replaces an installed executable with ReplaceFileW. A reader that holds the file must not fail that replace, and still
// reads the bytes it opened.
func TestOpenReadSharedLetsAnInstallerReplaceTheFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "defenseclaw-hook.exe")
	replacement := filepath.Join(dir, "defenseclaw-hook.exe.new")
	if err := os.WriteFile(path, []byte("MZ old"), 0o600); err != nil {
		t.Fatal(err)
	}

	// The class this fixes: a plain os.Open holds the name.
	held, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(replacement, []byte("MZ new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := replaceFileLikeSetup(replacement, path, path+".backup-1"); err == nil {
		t.Fatal("os.Open no longer blocks a replace; this test no longer shows the bug class")
	}
	_ = held.Close()

	shared, err := OpenReadShared(path)
	if err != nil {
		t.Fatal(err)
	}
	defer shared.Close()
	if err := replaceFileLikeSetup(replacement, path, path+".backup-2"); err != nil {
		t.Fatalf("a replace failed while OpenReadShared held the file: %v", err)
	}
	body, err := io.ReadAll(shared)
	if err != nil || !bytes.Equal(body, []byte("MZ old")) {
		t.Fatalf("the open handle read %q (%v), want the bytes it opened", body, err)
	}
	if current, err := ReadFileShared(path); err != nil || !bytes.Equal(current, []byte("MZ new")) {
		t.Fatalf("the name reads %q (%v) after the replace", current, err)
	}
}
