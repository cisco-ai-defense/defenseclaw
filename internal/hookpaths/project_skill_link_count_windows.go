// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookpaths

import (
	"os"

	"golang.org/x/sys/windows"
)

// projectSkillFileLinkCount is how many names the file at path has.
func projectSkillFileLinkCount(path string) (uint64, error) {
	if networkPathUnanswered(path) {
		return 0, networkShareError("stat", path)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, &os.PathError{Op: "stat", Path: path, Err: err}
	}
	handle, err := windows.CreateFile(name, 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return 0, &os.PathError{Op: "stat", Path: path, Err: err}
	}
	defer windows.CloseHandle(handle) //nolint:errcheck // a handle opened for attributes only
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return 0, &os.PathError{Op: "stat", Path: path, Err: err}
	}
	return uint64(info.NumberOfLinks), nil
}
