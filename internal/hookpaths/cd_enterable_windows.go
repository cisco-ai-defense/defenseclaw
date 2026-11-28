// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookpaths

import (
	"golang.org/x/sys/windows"
)

// fileTraverse is the FILE_TRAVERSE right of a directory (0x20).
const fileTraverse = 0x0020

// directoryEnterable reports a directory that cd can enter as this
// account. Windows has no search bit: SetCurrentDirectory opens the
// directory for traverse and synchronize with backup semantics, so the
// same open is the check (rel-1-0-6:GAP-0320 review 5 and 6).
func directoryEnterable(path string) bool {
	info, err := pathStat(path)
	if err != nil || !info.IsDir() {
		return false
	}
	// The open is made as readGated makes a read (rel-1-0-10:GAP-1264).
	_, err = readGatedValue("open", path, func(read string) (struct{}, error) {
		name, err := windows.UTF16PtrFromString(read)
		if err != nil {
			return struct{}{}, err
		}
		handle, err := windows.CreateFile(name, fileTraverse|windows.SYNCHRONIZE,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
			windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
		if err != nil {
			return struct{}{}, err
		}
		_ = windows.CloseHandle(handle)
		return struct{}{}, nil
	})
	return err == nil
}
