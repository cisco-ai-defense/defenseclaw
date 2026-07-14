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

package safefile

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func validateReadOwnerAndLinks(_ os.FileInfo, file *os.File) error {
	// The pre-open check has no stable handle on Windows. The same validation
	// runs immediately after CreateFile and again after the bounded read.
	if file == nil {
		return nil
	}
	handle := windows.Handle(file.Fd())
	var identity windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &identity); err != nil {
		return fmt.Errorf("inspect Windows file identity: %w", err)
	}
	if identity.NumberOfLinks != 1 {
		return fmt.Errorf("hard links are not allowed")
	}
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("inspect Windows file owner: %w", err)
	}
	if sd == nil {
		return fmt.Errorf("missing Windows security descriptor")
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("inspect Windows file owner: %w", err)
	}
	if !trustedWindowsReadOwner(owner) {
		return fmt.Errorf("Windows file owner %s is not Administrators, LocalSystem, or the current user", owner)
	}
	return nil
}

func openRegularNoFollow(path string) (*os.File, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil
}

func trustedWindowsReadOwner(owner *windows.SID) bool {
	if owner == nil {
		return false
	}
	if owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) || owner.IsWellKnown(windows.WinLocalSystemSid) {
		return true
	}
	current, err := windows.GetCurrentProcessToken().GetTokenUser()
	return err == nil && current != nil && current.User.Sid != nil && owner.Equals(current.User.Sid)
}
