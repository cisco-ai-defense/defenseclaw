//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"errors"
	"fmt"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

const managedFileRestrictiveAttributes = windows.FILE_ATTRIBUTE_READONLY |
	windows.FILE_ATTRIBUTE_HIDDEN | windows.FILE_ATTRIBUTE_SYSTEM

// clearManagedFileRestrictiveAttributes clears ReadOnly, Hidden and System
// from a managed regular file and logs the repair. Callers run it only after
// the object passed its structural check and descriptor repair.
func clearManagedFileRestrictiveAttributes(path string) {
	cleared, err := ClearRestrictiveFileAttributesNoFollow(path, managedFileRestrictiveAttributes)
	if err != nil {
		EmitResilienceEvent(MarkerAccept, map[string]string{
			"path":   path,
			"reason": fmt.Sprintf("restrictive file attributes were not cleared: %v", err),
		})
		return
	}
	if cleared != 0 {
		EmitResilienceEvent(MarkerRepair, map[string]string{
			"path":   path,
			"reason": fmt.Sprintf("cleared file attributes 0x%x on a managed file", cleared),
		})
	}
}

// ClearRestrictiveFileAttributesNoFollow clears mask from the regular file at
// path and returns the bits it cleared (0 when none were set or the file is
// gone). The change is made through one no-follow handle that must be a
// regular file with exactly one link, under an ancestor chain with no
// reparse point: hard links share attributes, and a by-path change could
// follow a junction.
func ClearRestrictiveFileAttributesNoFollow(path string, mask uint32) (uint32, error) {
	if mask == 0 {
		return 0, nil
	}
	if err := winpath.RejectReparseChain(filepath.Dir(path)); err != nil {
		return 0, err
	}
	pointer, err := winpath.UTF16Ptr(path)
	if err != nil {
		return 0, err
	}
	handle, err := windows.CreateFile(
		pointer,
		windows.FILE_READ_ATTRIBUTES|windows.FILE_WRITE_ATTRIBUTES|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return 0, err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return 0, fmt.Errorf("%s is not a regular file", path)
	}
	if info.NumberOfLinks != 1 {
		return 0, fmt.Errorf("%s has %d hard links", path, info.NumberOfLinks)
	}
	cleared := info.FileAttributes & mask
	if cleared == 0 {
		return 0, nil
	}
	remaining := info.FileAttributes &^ mask
	if remaining == 0 {
		remaining = windows.FILE_ATTRIBUTE_NORMAL
	}
	// Zero timestamps leave them unchanged.
	basic := setupBasicInfo{FileAttributes: remaining}
	if err := windows.SetFileInformationByHandle(handle, windows.FileBasicInfo,
		(*byte)(unsafe.Pointer(&basic)), uint32(unsafe.Sizeof(basic))); err != nil {
		return 0, err
	}
	return cleared, nil
}
