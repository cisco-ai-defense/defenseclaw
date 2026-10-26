// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// openNativeOTLPTakeBackMarker opens the marker itself, never a reparse
// point's target (file.Stat then reports the link, which is not regular),
// and denies writers while it is read.
func openNativeOTLPTakeBackMarker(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		name,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE,
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

// nativeOTLPTakeBackMarkerOwnerTrusted refuses a take-back-pending marker
// that another account owns (GAP-2021): its owner must be the owner of the
// account's managed data directory (the take-back writes it as that
// account), LocalSystem, Administrators, or this process's user. The owner
// is read from the opened handle, so it is the owner of the file that is
// read (GAP-2065).
func nativeOTLPTakeBackMarkerOwnerTrusted(path string, file *os.File, _ os.FileInfo) error {
	sd, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("take-back marker owner %s: %w", path, err)
	}
	fileOwner, _, err := sd.Owner()
	if err != nil || fileOwner == nil {
		return fmt.Errorf("take-back marker owner %s: no owner", path)
	}
	owner, err := fileOwner.Copy()
	if err != nil {
		return err
	}
	dirOwner, err := nativeOTLPTakeBackPathOwner(filepath.Dir(path))
	if err != nil {
		return err
	}
	if owner.Equals(dirOwner) || owner.IsWellKnown(windows.WinLocalSystemSid) ||
		owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return nil
	}
	if user, userErr := windows.GetCurrentProcessToken().GetTokenUser(); userErr == nil && owner.Equals(user.User.Sid) {
		return nil
	}
	return fmt.Errorf("take-back marker %s: owner %s is not the data directory's owner", path, owner.String())
}

func nativeOTLPTakeBackPathOwner(path string) (*windows.SID, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return nil, fmt.Errorf("take-back marker owner %s: %w", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return nil, fmt.Errorf("take-back marker owner %s: no owner", path)
	}
	return owner.Copy()
}
