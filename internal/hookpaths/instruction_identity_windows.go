// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookpaths

import (
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// maxInstructionLinkNames bounds the names one file is checked under.
const maxInstructionLinkNames = 1024

var (
	modKernel32            = windows.NewLazySystemDLL("kernel32.dll")
	procFindFirstFileNameW = modKernel32.NewProc("FindFirstFileNameW")
	procFindNextFileNameW  = modKernel32.NewProc("FindNextFileNameW")
)

// fileLinkNames lists every hard link of a file on a local volume
// (FindFirstFileNameW). complete is false when the list stopped early;
// listed is false when the volume cannot list them (a network share).
func fileLinkNames(path string) (names []string, complete, listed bool) {
	volume := filepath.VolumeName(path)
	if len(volume) != 2 || volume[1] != ':' {
		return nil, false, false
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, false, false
	}
	buffer := make([]uint16, 32768)
	length := uint32(len(buffer))
	handle, _, _ := procFindFirstFileNameW.Call(uintptr(unsafe.Pointer(name)), 0,
		uintptr(unsafe.Pointer(&length)), uintptr(unsafe.Pointer(&buffer[0])))
	if windows.Handle(handle) == windows.InvalidHandle {
		return nil, false, false
	}
	defer windows.FindClose(windows.Handle(handle))
	names = append(names, volume+windows.UTF16ToString(buffer))
	for len(names) < maxInstructionLinkNames {
		length = uint32(len(buffer))
		ok, _, callErr := procFindNextFileNameW.Call(handle,
			uintptr(unsafe.Pointer(&length)), uintptr(unsafe.Pointer(&buffer[0])))
		if ok == 0 {
			return names, callErr == windows.ERROR_HANDLE_EOF, true
		}
		names = append(names, volume+windows.UTF16ToString(buffer))
	}
	return names, false, true
}
