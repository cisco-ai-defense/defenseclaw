// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// assertCascadeRecordPrivate checks the record's real DACL: Go reports every
// Windows file as 0666, so the mode bits say nothing. The record has no DACL
// of its own; it inherits the private data dir's (OWNER RIGHTS and SYSTEM in
// a per-user install), so no other account may read or write it.
func assertCascadeRecordPrivate(t *testing.T, path string) {
	t.Helper()
	testenv.AssertPrivateFile(t, path)
	if err := safefile.PathUsersCanRead(path); err == nil {
		t.Fatalf("%s: ordinary users can read the cascade decision record", path)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("%s: no DACL: %v", path, err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}
		if ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Mask == 0 ||
			ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.Equals(user.User.Sid) && !sid.IsWellKnown(windows.WinLocalSystemSid) &&
			!sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) && !sid.IsWellKnown(windows.WinCreatorOwnerRightsSid) {
			t.Fatalf("%s: the cascade decision record grants mask 0x%x to another principal %s", path, uint32(ace.Mask), sid)
		}
	}
}
