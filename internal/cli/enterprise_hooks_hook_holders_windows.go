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

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// GAP-0755. Any account may open the hook with no sharing, because every
// account must be able to run it, and while that handle is open Windows
// refuses every start of the hook for every account. A swap cannot end this
// kind of hold: renaming a new file over the hook name needs the old file to
// share deletion, and a handle that shares nothing does not (tested natively:
// the rename fails with a sharing violation for as long as the handle
// lives). The only thing that ends the hold is closing the handle. The
// guardian runs as LocalSystem; it finds the other processes' handles on the
// hook by file identity and closes them in their owners. The file is not
// changed and no process is ended.

// windowsSystemExtendedHandleInformation is the NtQuerySystemInformation
// class that lists every handle with its owner and object type.
const windowsSystemExtendedHandleInformation = 64

// windowsHandleEntryEx is SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX.
type windowsHandleEntryEx struct {
	Object                uintptr
	UniqueProcessID       uintptr
	HandleValue           uintptr
	GrantedAccess         uint32
	CreatorBackTraceIndex uint16
	ObjectTypeIndex       uint16
	HandleAttributes      uint32
	Reserved              uint32
}

// windowsHandleSkipAccess are the granted-access masks of synchronous pipe
// and device handles on which a query can block for good; no disk file the
// hook could be is opened that way.
var windowsHandleSkipAccess = map[uint32]bool{0x0012019f: true, 0x001a019f: true, 0x00120189: true, 0x00100000: true}

// windowsQuerySystemHandles lists every handle of every process.
func windowsQuerySystemHandles() ([]windowsHandleEntryEx, error) {
	size := uint32(4 << 20)
	for attempt := 0; attempt < 10; attempt++ {
		buffer := make([]uint64, (size+7)/8)
		var needed uint32
		err := windows.NtQuerySystemInformation(windowsSystemExtendedHandleInformation, unsafe.Pointer(&buffer[0]), size, &needed)
		if err == nil {
			header := 2 * unsafe.Sizeof(uintptr(0))
			count := *(*uintptr)(unsafe.Pointer(&buffer[0]))
			if uintptr(size) < header || count > (uintptr(size)-header)/unsafe.Sizeof(windowsHandleEntryEx{}) {
				return nil, fmt.Errorf("the handle table answer is malformed (%d entries in %d bytes)", count, size)
			}
			entries := unsafe.Slice((*windowsHandleEntryEx)(unsafe.Add(unsafe.Pointer(&buffer[0]), header)), count)
			return append([]windowsHandleEntryEx(nil), entries...), nil
		}
		if !errors.Is(err, windows.STATUS_INFO_LENGTH_MISMATCH) {
			return nil, err
		}
		size = max(needed, size) + size/2 + 1<<16
	}
	return nil, errors.New("the handle table kept growing while it was read")
}

// windowsHookHolderIdentity is a file's volume and index.
type windowsHookHolderIdentity struct{ volume, high, low uint32 }

func windowsHandleIdentity(handle windows.Handle) (windowsHookHolderIdentity, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return windowsHookHolderIdentity{}, err
	}
	return windowsHookHolderIdentity{info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow}, nil
}

// closeWindowsFileHolders closes, in the processes that hold them, the
// handles other processes have open on the file at path, and returns one
// description per closed handle ("name (process id N)"). Its own process is
// skipped. A process it may not open (a protected one) is left alone and
// counted in the error text when nothing could be closed.
func closeWindowsFileHolders(path string) ([]string, error) {
	name, err := winpath.UTF16Ptr(path)
	if err != nil {
		return nil, err
	}
	// An attribute-only open takes no part in sharing, so it works while a
	// holder shares nothing. Its handle also shows the file type's index in
	// the handle table.
	probe, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s to identify it: %w", filepath.Base(path), err)
	}
	defer windows.CloseHandle(probe)
	want, err := windowsHandleIdentity(probe)
	if err != nil {
		return nil, err
	}
	entries, err := windowsQuerySystemHandles()
	if err != nil {
		return nil, fmt.Errorf("list the open handles: %w", err)
	}
	self := uintptr(os.Getpid())
	fileType := -1
	for _, entry := range entries {
		if entry.UniqueProcessID == self && entry.HandleValue == uintptr(probe) {
			fileType = int(entry.ObjectTypeIndex)
			break
		}
	}
	if fileType < 0 {
		return nil, errors.New("the file object type was not found in the handle table")
	}
	byProcess := map[uintptr][]uintptr{}
	for _, entry := range entries {
		if int(entry.ObjectTypeIndex) != fileType || entry.UniqueProcessID == self ||
			entry.UniqueProcessID <= 4 || windowsHandleSkipAccess[entry.GrantedAccess] {
			continue
		}
		byProcess[entry.UniqueProcessID] = append(byProcess[entry.UniqueProcessID], entry.HandleValue)
	}
	var closed []string
	unopened := 0
	var firstErr error
	for pid, handles := range byProcess {
		process, err := windows.OpenProcess(windows.PROCESS_DUP_HANDLE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
		if err != nil {
			unopened++
			continue
		}
		label := fmt.Sprintf("process id %d", pid)
		var image [4096]uint16
		imageSize := uint32(len(image))
		if windows.QueryFullProcessImageName(process, 0, &image[0], &imageSize) == nil {
			label = fmt.Sprintf("%s (process id %d)", filepath.Base(windows.UTF16ToString(image[:imageSize])), pid)
		}
		for _, value := range handles {
			var duplicate windows.Handle
			if err := windows.DuplicateHandle(process, windows.Handle(value), windows.CurrentProcess(), &duplicate, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
				continue
			}
			same := false
			if kind, err := windows.GetFileType(duplicate); err == nil && kind == windows.FILE_TYPE_DISK {
				if got, err := windowsHandleIdentity(duplicate); err == nil && got == want {
					same = true
				}
			}
			_ = windows.CloseHandle(duplicate)
			if !same {
				continue
			}
			if err := windows.DuplicateHandle(process, windows.Handle(value), 0, nil, 0, false, windows.DUPLICATE_CLOSE_SOURCE); err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("close a handle of %s: %w", label, err)
				}
				continue
			}
			closed = append(closed, label)
		}
		_ = windows.CloseHandle(process)
	}
	if len(closed) == 0 {
		if firstErr != nil {
			return nil, firstErr
		}
		if unopened > 0 {
			return nil, fmt.Errorf("no handle of another process was found on it (%d processes could not be opened)", unopened)
		}
		return nil, errors.New("no handle of another process was found on it")
	}
	return closed, nil
}

// windowsCloseHookHolders is the closing step; tests replace it.
var windowsCloseHookHolders = closeWindowsFileHolders

// windowsHookBinaryDeleteBlocked reports whether a handle on the hook shares
// no deletion, so that no swap of the name can succeed: an open for DELETE
// that allows every sharing mode is refused with a sharing violation. A
// writer that shares read and delete does not make it true.
var windowsHookBinaryDeleteBlocked = func(path string) bool {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	handle, err := windows.CreateFile(name, windows.DELETE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		return true
	}
	if err == nil {
		_ = windows.CloseHandle(handle)
	}
	return false
}
