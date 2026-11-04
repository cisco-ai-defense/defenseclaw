// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package inventory

import (
	"os"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// claudeDesktopReparsePoint reports a junction, symbolic link or other reparse
// point at path itself (not at a parent: the data folder's own chain is the
// user's profile). Attributes that cannot be read count as one: the folder is
// refused, never followed.
func claudeDesktopReparsePoint(path string) bool {
	ptr, err := winpath.UTF16Ptr(path)
	if err != nil {
		return true
	}
	attributes, err := windows.GetFileAttributes(ptr)
	return err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
}

// claudeDesktopOpenedIsChecked reports whether opened, a folder os.Open
// followed from path, is path itself and no reparse point: path is opened
// again without following a reparse point, that handle must carry no reparse
// attribute, and both handles must name the same file. A junction swapped in
// between the checks and os.Open fails one of them.
func claudeDesktopOpenedIsChecked(path string, opened *os.File) bool {
	ptr, err := winpath.UTF16Ptr(path)
	if err != nil {
		return false
	}
	handle, err := windows.CreateFile(ptr, 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(handle)
	var self, followed windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(handle, &self) != nil ||
		self.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		self.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return false
	}
	if windows.GetFileInformationByHandle(windows.Handle(opened.Fd()), &followed) != nil {
		return false
	}
	return self.VolumeSerialNumber == followed.VolumeSerialNumber &&
		self.FileIndexHigh == followed.FileIndexHigh && self.FileIndexLow == followed.FileIndexLow
}
