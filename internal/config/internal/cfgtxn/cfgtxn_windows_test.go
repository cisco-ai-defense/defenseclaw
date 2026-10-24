// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cfgtxn

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// Replacing a file keeps the access control the lifecycle gave it: the gateway
// service account reads the managed config, and a temp file inherits the
// directory's DACL instead (GAP-0135).
func TestWriteFileDurableKeepsTheDACLOfTheFileItReplaces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileDurable(path, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != "new" {
		t.Fatalf("content = %q", got)
	}
	after, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if sddl := after.String(); !strings.Contains(sddl, "(A;;FR;;;BU)") {
		t.Fatalf("replaced file lost its DACL: %s", sddl)
	}
}

// The .env lock is the one Python's file_lock.locked_file_update takes on
// Windows: msvcrt.locking at offset 0 locks byte 0 for length 1 on its own
// handle (#1099). While another handle holds that byte, LockFile waits and
// then reports ErrFileLockBusy; while LockFile holds it, another handle
// cannot take that byte; release frees it; the sentinel is never written.
func TestLockFileTakesThePythonSentinelByte(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	other, err := os.OpenFile(path+LockSuffix, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	h := windows.Handle(other.Fd())
	lockByte0 := func() error {
		return windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, new(windows.Overlapped))
	}
	unlockByte0 := func() {
		if err := windows.UnlockFileEx(h, 0, 1, 0, new(windows.Overlapped)); err != nil {
			t.Fatal(err)
		}
	}

	if err := lockByte0(); err != nil {
		t.Fatal(err)
	}
	if _, err := LockFile(context.Background(), path, 200*time.Millisecond); !errors.Is(err, ErrFileLockBusy) {
		t.Fatalf("LockFile while byte 0 is held = %v, want ErrFileLockBusy", err)
	}
	unlockByte0()

	release, err := LockFile(context.Background(), path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := lockByte0(); !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		t.Fatalf("taking byte 0 while LockFile holds it = %v, want ERROR_LOCK_VIOLATION", err)
	}
	release()
	if err := lockByte0(); err != nil {
		t.Fatalf("byte 0 after release: %v", err)
	}
	unlockByte0()
	if info, err := os.Stat(path + LockSuffix); err != nil || info.Size() != 0 {
		t.Fatalf("sentinel = %v, %v; want an empty file", info, err)
	}
}
