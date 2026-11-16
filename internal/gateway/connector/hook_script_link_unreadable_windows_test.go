// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// GAP-2022 (iteration 1 checker): a link SYSTEM made in place of a generated
// hook script carries only inherited entries, none for the account, so the
// render's Lstat was refused, the render failed and the gateway stayed down.
// The account owns its hook folder: the render removes the entry it cannot
// read and writes a regular file, leaving the link's target alone.
func TestWriteHookScriptsReplacesALinkTheAccountCannotRead(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		t.Skip("LocalSystem is granted on the link; run as an interactive account")
	}
	hookDir := filepath.Join(t.TempDir(), "hooks")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "elsewhere.sh")
	original := []byte("#!/bin/sh\nexit 0\n")
	if err := os.WriteFile(target, original, 0o600); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(hookDir, "inspect-tool.sh")
	if err := os.Symlink(target, script); err != nil {
		t.Skipf("cannot create a symlink here: %v", err)
	}
	// Only SYSTEM on the link itself, as a SYSTEM-made link in a user's
	// folder reads to that user.
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(script)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(name, windows.WRITE_DAC|windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatal(err)
	}
	err = windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
	windows.CloseHandle(h)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(script); err == nil {
		t.Skip("fixture: this account can still look at the link (it holds a privilege that bypasses the DACL)")
	}

	if err := writeHookScriptsCommon(hookDir, "127.0.0.1:18970", "test-token", nil); err != nil {
		t.Fatalf("writeHookScriptsCommon: %v", err)
	}
	info, err := os.Lstat(script)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("inspect-tool.sh is %v, want a regular file", info.Mode())
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("the link target was rewritten: %q", got)
	}
}
