// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookpaths

import (
	"os"
	"strconv"
	"syscall"
)

// fileIdentityForPath uses the volume and file index of the opened Windows
// file. Its identity remains stable across edits and changes on replacement.
func fileIdentityForPath(path string, _ os.FileInfo) string {
	return handleIdentity(path, 0)
}

// directoryIdentityForPath is fileIdentityForPath for a directory, which
// opens only with backup semantics.
func directoryIdentityForPath(path string, _ os.FileInfo) string {
	return handleIdentity(path, syscall.FILE_FLAG_BACKUP_SEMANTICS)
}

// handleIdentity is read as readGated reads (the path the share gate read,
// its last component held, the answer discarded when the hold saw it
// change); an identity that cannot be read so is "" (rel-1-0-10:GAP-1264).
func handleIdentity(path string, flags uint32) string {
	data, err := handleInformation(path, flags)
	if err != nil {
		return ""
	}
	return strconv.FormatUint(uint64(data.VolumeSerialNumber), 16) + ":" +
		strconv.FormatUint(uint64(data.FileIndexHigh), 16) + ":" +
		strconv.FormatUint(uint64(data.FileIndexLow), 16)
}

// handleInformation opens path for no data access, following it, and reads
// its file information, as readGated reads.
func handleInformation(path string, flags uint32) (syscall.ByHandleFileInformation, error) {
	return readGatedValue("open", path, func(read string) (syscall.ByHandleFileInformation, error) {
		var data syscall.ByHandleFileInformation
		name, err := syscall.UTF16PtrFromString(read)
		if err != nil {
			return data, err
		}
		handle, err := syscall.CreateFile(name, 0,
			syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
			nil, syscall.OPEN_EXISTING, flags, 0)
		if err != nil {
			return data, err
		}
		defer syscall.CloseHandle(handle) //nolint:errcheck // a handle opened for attributes only
		err = syscall.GetFileInformationByHandle(handle, &data)
		return data, err
	})
}

// linkCount returns the number of hard links to a file. An unknown count is
// reported as more than one so the caller fails closed.
func linkCount(path string, _ os.FileInfo) uint64 {
	data, err := handleInformation(path, syscall.FILE_FLAG_BACKUP_SEMANTICS)
	if err != nil {
		return 2
	}
	return uint64(data.NumberOfLinks)
}
