// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"os"

	"golang.org/x/sys/windows"
)

// openCoworkActivityRecord opens the Cowork activity record for reading as
// the reparse point itself when it is one (FILE_FLAG_OPEN_REPARSE_POINT, the
// Windows O_NOFOLLOW), so the caller's regular-file check of the opened
// handle refuses a symbolic link or junction swapped in after its Lstat.
// Windows has no FIFOs to block on.
func openCoworkActivityRecord(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil
}
