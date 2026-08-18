// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"fmt"
	"os"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

type atomicTransformWindowsFileIDInfo struct {
	VolumeSerialNumber uint64
	FileID             [16]byte
}

func atomicTransformOpenFileIdentity(file *os.File) (string, error) {
	var info atomicTransformWindowsFileIDInfo
	if err := windows.GetFileInformationByHandleEx(
		windows.Handle(file.Fd()),
		windows.FileIdInfo,
		(*byte)(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	); err != nil {
		return "", err
	}
	return fmt.Sprintf(
		"windows:%016x:%x",
		info.VolumeSerialNumber,
		info.FileID,
	), nil
}

func atomicTransformDirectoryIdentity(path string) (string, error) {
	ptr, err := winpath.UTF16Ptr(path)
	if err != nil {
		return "", err
	}
	handle, err := windows.CreateFile(
		ptr,
		windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return "", err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return "", fmt.Errorf("wrap directory identity handle: %s", path)
	}
	defer file.Close()
	return atomicTransformOpenFileIdentity(file)
}
