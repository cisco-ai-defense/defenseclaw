// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package daemon

import (
	"errors"
	"fmt"
	"io"
	"os"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

const maxManagedPIDFileBytes = 64 << 10

// removePIDFileIf atomically binds the content comparison and deletion to one
// Windows file object. The handle shares only reads, so both an in-place writer
// and a concurrent safefile.WritePrivate/MoveFileEx replacement must wait until
// the old record is either rejected or marked for deletion.
// SetFileInformationByHandle then deletes that exact opened object rather than
// whichever record happens to occupy the pathname after the comparison.
func removePIDFileIf(path string, matches func([]byte) bool) error {
	if matches == nil {
		return errors.New("daemon: nil PID file matcher")
	}
	pathPtr, err := winpath.UTF16Ptr(path)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ|windows.DELETE,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return nil
		}
		return err
	}

	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return fmt.Errorf("daemon: wrap PID file handle: %s", path)
	}
	defer file.Close()

	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("daemon: refusing reparse-point PID file: %s", path)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		return fmt.Errorf("daemon: PID file is a directory: %s", path)
	}

	data, err := io.ReadAll(io.LimitReader(file, maxManagedPIDFileBytes+1))
	if err != nil {
		return err
	}
	if len(data) > maxManagedPIDFileBytes {
		return fmt.Errorf("daemon: PID file exceeds %d bytes", maxManagedPIDFileBytes)
	}
	if !matches(data) {
		return nil
	}

	deleteFile := uint32(1) // FILE_DISPOSITION_INFO.DeleteFile is a Win32 BOOL.
	if err := windows.SetFileInformationByHandle(
		handle,
		windows.FileDispositionInfo,
		(*byte)(unsafe.Pointer(&deleteFile)),
		uint32(unsafe.Sizeof(deleteFile)),
	); err != nil {
		return err
	}
	return nil
}
