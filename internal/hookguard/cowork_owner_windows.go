// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookguard

import (
	"errors"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// coworkMarkerOwnerTrusted reads the owners of the removal marker and of the
// folder that holds it, each on a handle opened without following a reparse
// point, and applies coworkOwnersTrusted. Any error keeps the installed path.
func coworkMarkerOwnerTrusted(marker string) bool {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return false
	}
	markerOwner, err := coworkPathOwner(marker, false)
	if err != nil {
		return false
	}
	folderOwner, err := coworkPathOwner(filepath.Dir(marker), true)
	if err != nil {
		return false
	}
	return coworkOwnersTrusted(markerOwner, folderOwner, user.User.Sid.String())
}

// coworkPathOwner returns the owner SID of path, which must be a directory
// when directory is set and a file otherwise, and never a reparse point.
func coworkPathOwner(path string, directory bool) (string, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	handle, err := windows.CreateFile(
		name,
		windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(handle)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return "", err
	}
	isDirectory := info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || isDirectory != directory {
		return "", errors.New("unexpected file type")
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return "", err
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return "", err
	}
	if owner == nil {
		return "", errors.New("no owner")
	}
	return owner.String(), nil
}
