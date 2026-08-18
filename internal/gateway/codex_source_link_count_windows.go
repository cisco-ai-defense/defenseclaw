// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"os"

	"golang.org/x/sys/windows"
)

// Windows' os.FileInfo.Sys value does not expose a link count. Open the exact
// leaf without following reparse points and ask the kernel for the handle's
// NumberOfLinks instead. Failure is intentionally untrusted.
func codexSourceFileHasSingleLink(path string, _ os.FileInfo) bool {
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	handle, err := windows.CreateFile(
		pathPointer,
		windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return false
	}
	defer func() { _ = windows.CloseHandle(handle) }()

	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		return false
	}
	return information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0 &&
		information.NumberOfLinks == 1
}
