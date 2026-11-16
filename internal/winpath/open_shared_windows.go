// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package winpath

import (
	"os"

	"golang.org/x/sys/windows"
)

// OpenReadShared opens path for reading as os.Open does, but also shares
// delete access, so another process can rename or replace the file while the
// handle is open. os.Open shares no delete access: a read-only check of the
// installed hook binary, which runs on every hook call, made the published
// older Setup's one-shot [IO.File]::Replace of that binary fail with a
// sharing violation, and a downgrade under hook traffic rolled back
// (GAP-0200). A running image does not block the replace; only such a
// handle does. Callers that need the bytes to stay put keep their own
// identity checks; a replaced name no longer names the handle's file.
func OpenReadShared(path string) (*os.File, error) {
	name, err := UTF16Ptr(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	handle, err := windows.CreateFile(
		name,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(handle), path), nil
}
