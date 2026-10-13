// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookpaths

import (
	"os"
	"syscall"
)

// linkCount returns the number of hard links to a file. An unknown count is
// reported as more than one so the caller fails closed.
func linkCount(path string, _ os.FileInfo) uint64 {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 2
	}
	handle, err := syscall.CreateFile(name, 0,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return 2
	}
	defer syscall.CloseHandle(handle)
	var data syscall.ByHandleFileInformation
	if syscall.GetFileInformationByHandle(handle, &data) != nil {
		return 2
	}
	return uint64(data.NumberOfLinks)
}
