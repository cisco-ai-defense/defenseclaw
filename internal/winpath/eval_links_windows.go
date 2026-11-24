// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package winpath

import (
	"errors"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// evalLinks opens path with no data access, following every link, and reads
// the final path of the handle. The open needs no right on the file and
// conflicts with no other open of it.
func evalLinks(path string) (string, error) {
	if path == "" {
		return filepath.EvalSymlinks(path)
	}
	handle, err := openForFinalPath(path, 0, 0)
	if errors.Is(err, windows.ERROR_CANT_ACCESS_FILE) {
		// The system does not open some reparse points (an app execution
		// alias): such a point is its own place unless it names another.
		handle, err = ownFinalPathHandle(path)
	}
	if err != nil {
		return "", &os.PathError{Op: "evallinks", Path: path, Err: err}
	}
	defer windows.CloseHandle(handle)
	final, err := finalPathByHandle(handle)
	if err != nil {
		return "", &os.PathError{Op: "evallinks", Path: path, Err: err}
	}
	return plainWindowsPath(final), nil
}

func openForFinalPath(path string, access, flags uint32) (windows.Handle, error) {
	name, err := UTF16Ptr(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return windows.CreateFile(name, access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|flags, 0)
}

// ownFinalPathHandle opens the reparse point at path itself and keeps the
// handle only when the point names no other file system place (it is not a
// junction, a mount point or a symbolic link).
func ownFinalPathHandle(path string) (windows.Handle, error) {
	handle, err := openForFinalPath(path, windows.FILE_READ_ATTRIBUTES, windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if err != nil {
		return windows.InvalidHandle, err
	}
	var info struct {
		FileAttributes uint32
		ReparseTag     uint32
	}
	if err := windows.GetFileInformationByHandleEx(handle, windows.FileAttributeTagInfo,
		(*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		windows.CloseHandle(handle)
		return windows.InvalidHandle, err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0 || info.ReparseTag&reparseTagNameSurrogate != 0 {
		windows.CloseHandle(handle)
		return windows.InvalidHandle, windows.ERROR_CANT_ACCESS_FILE
	}
	return handle, nil
}
