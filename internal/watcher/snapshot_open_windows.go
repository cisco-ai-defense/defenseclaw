// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package watcher

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func openSnapshotFile(path string) (*os.File, error) {
	return os.Open(path)
}

// snapshotFileIdentity names the volume and file ID of the entry a path
// resolves to.
func snapshotFileIdentity(path string) (string, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	handle, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(handle)
	var data windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &data); err != nil {
		return "", err
	}
	return fmt.Sprintf("%d:%d", data.VolumeSerialNumber,
		uint64(data.FileIndexHigh)<<32|uint64(data.FileIndexLow)), nil
}
