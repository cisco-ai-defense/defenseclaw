// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// replaceLikeDiscovery renames source over destination as Python discovery
// replaces agent_discovery.json (file_permissions.replace_file_durable): one
// POSIX-semantics rename (FileRenameInfoEx), which a reader that shares
// delete does not block. It is not retried, so every reader that does not
// share delete shows as a failed replace.
func replaceLikeDiscovery(source, destination string) error {
	from, err := winpath.UTF16Ptr(source)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(from, windows.DELETE|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	name, err := windows.UTF16FromString(destination)
	if err != nil {
		return err
	}
	type fileRenameInfo struct {
		Flags          uint32
		RootDirectory  windows.Handle
		FileNameLength uint32
		FileName       [1]uint16
	}
	size := unsafe.Offsetof(fileRenameInfo{}.FileName) + uintptr(len(name))*2
	buffer := make([]uint64, (size+7)/8)
	info := (*fileRenameInfo)(unsafe.Pointer(&buffer[0]))
	info.Flags = 0x1 | 0x2 // FILE_RENAME_FLAG_REPLACE_IF_EXISTS | FILE_RENAME_FLAG_POSIX_SEMANTICS
	info.FileNameLength = uint32((len(name) - 1) * 2)
	copy(unsafe.Slice(&info.FileName[0], len(name)), name)
	return windows.SetFileInformationByHandle(handle, windows.FileRenameInfoEx, (*byte)(unsafe.Pointer(&buffer[0])), uint32(size))
}
