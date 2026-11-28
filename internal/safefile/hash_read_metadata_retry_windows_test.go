// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package safefile

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// moveChangeTimeOnly moves only the file's change time, as an ACL or extended
// attribute write does. os.Chmod is no such change on Windows: it only flips
// the read-only attribute, and only when the owner write bit changes, and an
// attribute change is not metadata-only to readStabilitySnapshot (GAP-2033).
func moveChangeTimeOnly(t *testing.T, path string, call int) {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(name,
		windows.FILE_READ_ATTRIBUTES|windows.FILE_WRITE_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	var basic readStabilityWindowsBasicInfo
	size := uint32(unsafe.Sizeof(basic))
	if err := windows.GetFileInformationByHandleEx(handle, windows.FileBasicInfo, (*byte)(unsafe.Pointer(&basic)), size); err != nil {
		t.Fatal(err)
	}
	// Zero leaves the other times and the attributes as they are.
	set := readStabilityWindowsBasicInfo{changeTime: basic.changeTime + int64(call)*10_000_000}
	if err := windows.SetFileInformationByHandle(handle, windows.FileBasicInfo, (*byte)(unsafe.Pointer(&set)), size); err != nil {
		t.Fatal(err)
	}
}
