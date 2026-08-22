// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package safefile

import (
	"fmt"
	"os"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

func protectFileWhileInUse(path string) error {
	expected, err := validateRegularFilePath(path)
	if err != nil {
		return err
	}
	ptr, err := winpath.UTF16Ptr(path)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(
		ptr,
		windows.READ_CONTROL|windows.WRITE_DAC|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return fmt.Errorf("safefile: wrap protected file handle: %s", path)
	}
	defer file.Close()

	opened, err := file.Stat()
	if err != nil {
		return err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(expected, opened) {
		return fmt.Errorf("safefile: file changed while opening: %s", path)
	}
	current, err := validateRegularFilePath(path)
	if err != nil {
		return err
	}
	if !os.SameFile(opened, current) {
		return fmt.Errorf("safefile: file changed while validating: %s", path)
	}

	sd, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION,
	)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	user, acl, err := privateDACLForCurrentUser(false)
	if err != nil {
		return err
	}
	if owner == nil || !owner.Equals(user) {
		return fmt.Errorf("safefile: refusing foreign-owned path: %s", path)
	}
	if err := windows.SetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	); err != nil {
		return err
	}
	current, err = validateRegularFilePath(path)
	if err != nil {
		return err
	}
	if !os.SameFile(opened, current) {
		return fmt.Errorf("safefile: file changed while protecting: %s", path)
	}
	return ValidatePrivateHandle(handle)
}
