// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package testenv

import (
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

func AssertPrivateFile(t testing.TB, path string) {
	t.Helper()
	assertPrivateDACL(t, path)
}

func AssertPrivateDirectory(t testing.TB, path string) {
	t.Helper()
	assertPrivateDACL(t, path)
}

// PrivateTempDir creates a disposable directory beneath LocalAppData rather
// than the shared Windows Temp tree, whose inherited ACL intentionally grants
// the test runner service account write access.
func PrivateTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(os.Getenv("LOCALAPPDATA"), "DefenseClaw-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("remove private temp dir %s: %v", dir, err)
		}
	})
	// Some Windows CI images assign newly created objects to the built-in
	// Administrators group. This path was just created by this helper, so make
	// the current user its explicit owner before exercising the production
	// refusal to rewrite genuinely foreign-owned directories.
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("current token user: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(
		dir,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION,
		user.User.Sid,
		nil,
		nil,
		nil,
	); err != nil {
		t.Fatalf("own private temp dir: %v", err)
	}
	if err := safefile.ProtectDirectory(dir); err != nil {
		t.Fatalf("protect private temp dir: %v", err)
	}
	return dir
}

func assertPrivateDACL(t testing.TB, path string) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("inspect private path %s DACL: %v", path, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("private path %s has no DACL: %v", path, err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatalf("current token user: %v", err)
	}
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
			t.Fatalf("inspect private path %s ACE %d: %v", path, i, err)
		}
		if ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		trusted := sid.Equals(user.User.Sid) || sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) || sid.IsWellKnown(windows.WinCreatorOwnerRightsSid)
		writeLike := ace.Mask&(windows.GENERIC_ALL|windows.GENERIC_WRITE|windows.DELETE|windows.WRITE_DAC|windows.WRITE_OWNER|windows.FILE_WRITE_DATA|windows.FILE_APPEND_DATA|windows.FILE_WRITE_EA|windows.FILE_WRITE_ATTRIBUTES) != 0
		if writeLike && !trusted {
			t.Fatalf("private path %s grants write-like mask 0x%x to %s", path, uint32(ace.Mask), sid)
		}
	}
}
