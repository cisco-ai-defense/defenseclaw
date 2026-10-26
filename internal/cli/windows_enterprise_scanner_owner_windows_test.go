// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// GAP-1718: after the scanner runtime work adopts Administrators as the
// default owner, a file this elevated process creates is owned by
// Administrators even when the token belongs to the built-in Administrator
// (RID 500, no Admin Approval Mode), whose default owner is its own SID.
func TestWindowsScannerRuntimeFilesAreOwnedByAdministrators(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated administrator token")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		t.Skip("LocalSystem owns what it creates as SYSTEM")
	}
	restore, err := adoptWindowsAdministratorsDefaultOwner()
	if err != nil {
		t.Fatalf("adopt Administrators as the default owner: %v", err)
	}
	defer restore()
	path := filepath.Join(t.TempDir(), "admission.json")
	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	owned, err := windowsPathOwnedByAdministrators(path)
	if err != nil || !owned {
		t.Fatalf("a file written after the adoption is not owned by Administrators: owned=%t err=%v", owned, err)
	}
}
