// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookpaths

import (
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// actionProcessProfileDirectory is the profile folder of the user this
// process runs as; a variable so a test can place the home there.
var actionProcessProfileDirectory = func() (string, error) {
	return windows.GetCurrentProcessToken().GetUserProfileDirectory()
}

// actionProcessOwnsHome reports a process that runs as the user of the
// home: its profile folder is the home. Such a process (a per-user gateway,
// the hook client) cannot list a folder the user Git Bash cannot list
// either, such as the legacy junctions of a profile (Application Data,
// Cookies, My Documents ...) that deny listing to everyone, so the shell
// expands nothing there (rel-1-0-6:GAP-0211, as GAP-1739 on Linux). A
// service with another profile keeps such a folder as unproved.
func actionProcessOwnsHome(home string) bool {
	profile, err := actionProcessProfileDirectory()
	if err != nil || profile == "" || home == "" {
		return false
	}
	return samePathName(filepath.Clean(profile), filepath.Clean(home))
}

// actionGlobDirDeniesEveryoneList reports a directory whose own access
// list denies listing (FILE_LIST_DIRECTORY) to Everyone, as the legacy
// junctions of every Windows profile do (Application Data, Cookies, My
// Documents ...). No account lists it without the backup privilege, so a
// user Git Bash expands nothing there whichever process reads the
// pattern: a managed gateway service judges it as the per-user gateway
// does (rel-1-0-6:GAP-0211, parity). A deny entry that only some accounts
// carry, or one that is only inherited by children, proves nothing.
func actionGlobDirDeniesEveryoneList(dir string) bool {
	if networkPathUnanswered(dir) {
		return false
	}
	descriptor, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil || descriptor == nil {
		return false
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return false
	}
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		return false
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(dacl, i, &ace) != nil || ace == nil {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_DENIED_ACE_TYPE || ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if ace.Mask&windows.FILE_LIST_DIRECTORY != 0 && sid.Equals(everyone) {
			return true
		}
	}
	return false
}
