//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package local

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func secureOpenAppend(path string) (*os.File, os.FileInfo, int64, error) {
	if err := prepareSecureParent(path); err != nil {
		return nil, nil, 0, err
	}
	file, err := openWindowsFile(path, windows.FILE_APPEND_DATA|windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL, windows.OPEN_ALWAYS, true)
	if err != nil {
		return nil, nil, 0, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, 0, ioFailure()
	}
	if err := validateSecureFileInfo(info); err != nil {
		_ = file.Close()
		return nil, nil, 0, err
	}
	return file, info, info.Size(), nil
}

func secureOpenRead(path string) (*os.File, os.FileInfo, error) {
	if err := prepareSecureParent(path); err != nil {
		return nil, nil, err
	}
	file, err := openWindowsFile(path, windows.GENERIC_READ|windows.READ_CONTROL, windows.OPEN_EXISTING, false)
	if err != nil {
		return nil, nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, ioFailure()
	}
	if err := validateSecureFileInfo(info); err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	return file, info, nil
}

func secureCreateExclusive(path string) (*os.File, error) {
	if err := prepareSecureParent(path); err != nil {
		return nil, err
	}
	return openWindowsFile(path, windows.GENERIC_WRITE|windows.READ_CONTROL, windows.CREATE_NEW, true)
}

// MoveFile fails when destination already exists, unlike replacement-oriented
// rename helpers. This pins the same no-clobber backup contract as Unix.
func secureMoveNoReplace(source, destination string) error {
	from, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return unsafeFailure()
	}
	to, err := windows.UTF16PtrFromString(destination)
	if err != nil {
		return unsafeFailure()
	}
	if err := windows.MoveFile(from, to); err != nil {
		return ioFailure()
	}
	return nil
}

func openWindowsFile(path string, access uint32, disposition uint32, protectNew bool) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, unsafeFailure()
	}
	var attributes *windows.SecurityAttributes
	if protectNew {
		user, err := windows.GetCurrentProcessToken().GetTokenUser()
		if err != nil || user == nil || user.User.Sid == nil {
			return nil, ioFailure()
		}
		descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.User.Sid.String() + ")(A;;FA;;;SY)(A;;FA;;;BA)")
		if err != nil {
			return nil, ioFailure()
		}
		attributes = &windows.SecurityAttributes{
			Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor,
		}
	}
	handle, err := windows.CreateFile(name, access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, attributes, disposition,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, ioFailure()
	}
	var details windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &details); err != nil ||
		details.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || details.NumberOfLinks != 1 {
		_ = windows.CloseHandle(handle)
		if err == nil {
			return nil, unsafeFailure()
		}
		return nil, ioFailure()
	}
	if err := validateWindowsHandleACL(handle, true); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, ioFailure()
	}
	return file, nil
}

func validateSecureFileInfo(info os.FileInfo) error {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return unsafeFailure()
	}
	return nil
}

func validateSecureOpenFile(file *os.File) error {
	if file == nil {
		return unsafeFailure()
	}
	var details windows.ByHandleFileInformation
	handle := windows.Handle(file.Fd())
	if err := windows.GetFileInformationByHandle(handle, &details); err != nil {
		return ioFailure()
	}
	if details.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || details.NumberOfLinks != 1 {
		return unsafeFailure()
	}
	return validateWindowsHandleACL(handle, true)
}

func validateSecureDirectory(path string, info os.FileInfo) error {
	if info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return unsafeFailure()
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return unsafeFailure()
	}
	handle, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return ioFailure()
	}
	defer windows.CloseHandle(handle)
	var details windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &details); err != nil {
		return ioFailure()
	}
	if details.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return unsafeFailure()
	}
	return validateWindowsHandleACL(handle, false)
}

func validateWindowsHandleACL(handle windows.Handle, ownerOnly bool) error {
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || descriptor == nil {
		return ioFailure()
	}
	owner, _, err := descriptor.Owner()
	if err != nil || !windowsAllowedPrincipal(owner) {
		return unsafeFailure()
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return unsafeFailure()
	}
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			return ioFailure()
		}
		if ace == nil || ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Mask == 0 {
			continue
		}
		switch ace.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		case 0x5, 0x9, 0xB: // object/callback allow ACEs need shape-specific parsing.
			return unsafeFailure()
		default:
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !windowsAllowedPrincipal(sid) && (ownerOnly || windowsWriteLikeAccess(ace.Mask)) {
			return unsafeFailure()
		}
	}
	return nil
}

func windowsWriteLikeAccess(mask windows.ACCESS_MASK) bool {
	const fileDeleteChild windows.ACCESS_MASK = 0x00000040
	writeLike := windows.ACCESS_MASK(
		windows.GENERIC_ALL | windows.GENERIC_WRITE | windows.DELETE |
			windows.WRITE_DAC | windows.WRITE_OWNER | windows.FILE_WRITE_DATA |
			windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES,
	)
	return mask&(writeLike|fileDeleteChild) != 0
}

func windowsAllowedPrincipal(sid *windows.SID) bool {
	if sid == nil {
		return false
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err == nil && user != nil && user.User.Sid != nil && sid.Equals(user.User.Sid) {
		return true
	}
	return sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid)
}
