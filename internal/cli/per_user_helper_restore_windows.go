// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// install.ps1 keeps a recorded copy of defenseclaw-hook-guard.exe in the
// installer folder (GAP-2525), so a 1.0.2 or 1.0.3 roll-forward that leaves
// the guard out gets it back at the next gateway start.
func perUserHelperRestoreSupported() bool { return true }

// perUserPrivateDir: a real folder (no reparse point) that only this account,
// SYSTEM or Administrators can change.
func perUserPrivateDir(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	return perUserPathOnlyThisAccountWrites(path, true)
}

// perUserOwnedPrivateFile: a regular file with one link that only this
// account, SYSTEM or Administrators can change.
func perUserOwnedPrivateFile(path string, info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() {
		return false
	}
	return perUserPathOnlyThisAccountWrites(path, false)
}

func perUserPathOnlyThisAccountWrites(path string, dir bool) bool {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if dir {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	handle, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(handle)
	var details windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &details); err != nil {
		return false
	}
	if details.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (!dir && details.NumberOfLinks != 1) {
		return false
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || descriptor == nil {
		return false
	}
	owner, _, err := descriptor.Owner()
	if err != nil || !perUserAllowedWriter(owner) {
		return false
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return false
	}
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			return false
		}
		if ace == nil || ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Mask == 0 {
			continue
		}
		switch ace.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		case 0x5, 0x9, 0xB: // object and callback allow entries: not parsed, refuse.
			return false
		default:
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if perUserWriteLikeAccess(ace.Mask) && !sid.IsWellKnown(windows.WinCreatorOwnerRightsSid) && !perUserAllowedWriter(sid) {
			return false
		}
	}
	return true
}

func perUserWriteLikeAccess(mask windows.ACCESS_MASK) bool {
	const fileDeleteChild windows.ACCESS_MASK = 0x00000040
	writeLike := windows.ACCESS_MASK(
		windows.GENERIC_ALL | windows.GENERIC_WRITE | windows.DELETE |
			windows.WRITE_DAC | windows.WRITE_OWNER | windows.FILE_WRITE_DATA |
			windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES,
	)
	return mask&(writeLike|fileDeleteChild) != 0
}

func perUserAllowedWriter(sid *windows.SID) bool {
	if sid == nil {
		return false
	}
	if sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return true
	}
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	return err == nil && user != nil && user.User.Sid != nil && sid.Equals(user.User.Sid)
}
