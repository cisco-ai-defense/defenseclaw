// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"os"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// openHookConfigForRead opens an agent config for a read-only presence check.
// os.Open omits FILE_SHARE_DELETE, so a concurrent check would make the
// connector's atomic replacement of the same file fail with ACCESS_DENIED.
// Sharing delete lets the replacement proceed; the reader keeps the bytes of
// the file it opened. Like os.Open, this follows links and opens directories
// so readHookConfigFile can report a non-regular path precisely.
func openHookConfigForRead(path string) (*os.File, error) {
	name, err := winpath.UTF16Ptr(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		name,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(handle), path), nil
}
