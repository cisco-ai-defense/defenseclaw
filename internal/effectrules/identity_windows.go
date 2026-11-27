// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package effectrules

import (
	"syscall"
)

// DiskIdentity reads a regular file's volume serial, file index and link
// count. The handle is opened for attributes only (no read or write access),
// sharing everything, so it never blocks or is blocked by the file's users.
func DiskIdentity(path string) (FileID, bool) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return FileID{}, false
	}
	h, err := syscall.CreateFile(p, 0,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return FileID{}, false
	}
	defer syscall.CloseHandle(h)
	var fi syscall.ByHandleFileInformation
	if syscall.GetFileInformationByHandle(h, &fi) != nil || fi.FileAttributes&syscall.FILE_ATTRIBUTE_DIRECTORY != 0 {
		return FileID{}, false
	}
	return FileID{Dev: uint64(fi.VolumeSerialNumber), Ino: uint64(fi.FileIndexHigh)<<32 | uint64(fi.FileIndexLow), Links: uint64(fi.NumberOfLinks)}, true
}
