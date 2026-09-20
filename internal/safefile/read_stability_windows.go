// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package safefile

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

type readStabilityWindowsBasicInfo struct {
	creationTime   int64
	lastAccessTime int64
	lastWriteTime  int64
	changeTime     int64
	fileAttributes uint32
	_              uint32
}

func readStabilitySnapshot(file *os.File) (readStability, error) {
	info, err := file.Stat()
	if err != nil {
		return readStability{}, err
	}
	var basic readStabilityWindowsBasicInfo
	if err := windows.GetFileInformationByHandleEx(
		windows.Handle(file.Fd()),
		windows.FileBasicInfo,
		(*byte)(unsafe.Pointer(&basic)),
		uint32(unsafe.Sizeof(basic)),
	); err != nil {
		return readStability{}, err
	}
	return readStability{
		size:       info.Size(),
		modified:   basic.lastWriteTime,
		changed:    basic.changeTime,
		attributes: basic.fileAttributes,
	}, nil
}
