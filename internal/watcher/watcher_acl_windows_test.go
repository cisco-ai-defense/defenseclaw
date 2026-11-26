// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package watcher

import (
	"os/exec"
	"testing"

	"golang.org/x/sys/windows"
)

// denyAccessForTest is the Windows twin of os.Chmod(path, 0) and the read-only
// modes the POSIX tests use: it puts a DENY entry for the account running the
// test on path, with the icacls specific rights (for example "RD" to list a
// folder, "WD,AD" to add files and folders to it). The owner can always change
// the access list, so the returned restore func (also run at test cleanup)
// removes the entry again.
func denyAccessForTest(t *testing.T, path, rights string) (restore func()) {
	t.Helper()
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatalf("read the test account: %v", err)
	}
	sid := "*" + user.User.Sid.String()
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("icacls", append([]string{path}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("icacls %v: %v: %s", args, err, out)
		}
	}
	run("/deny", sid+":("+rights+")")
	restored := false
	restore = func() {
		if restored {
			return
		}
		restored = true
		_ = exec.Command("icacls", path, "/remove:d", sid).Run()
	}
	t.Cleanup(restore)
	return restore
}

// holdOpenForTest keeps path open without delete sharing, so a rename or a
// removal of it (or of its folder) fails with a sharing violation: the Windows
// twin of a folder the process may not delete from. The returned release func
// (also run at test cleanup) closes the handle.
func holdOpenForTest(t *testing.T, path string) (release func()) {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatalf("hold %s open: %v", path, err)
	}
	released := false
	release = func() {
		if !released {
			released = true
			_ = windows.CloseHandle(handle)
		}
	}
	t.Cleanup(release)
	return release
}
