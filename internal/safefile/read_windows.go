// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package safefile

import (
	"os"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

func openRegularRead(path string) (*os.File, error) {
	extended, err := winpath.Extended(path)
	if err != nil {
		return nil, err
	}
	pathPtr, err := windows.UTF16PtrFromString(extended)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ,
		// Deny write sharing for the lifetime of the read. NTFS may defer
		// LastWriteTime updates until the final writer closes, so metadata
		// snapshots alone cannot detect an equal-length overwrite through a
		// writer handle that was already open. Delete sharing remains enabled;
		// the post-read pathname identity check rejects replacement.
		windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil
}
