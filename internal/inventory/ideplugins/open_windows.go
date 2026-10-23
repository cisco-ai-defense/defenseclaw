// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package ideplugins

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// openNonblocking opens path read-only. The caller has already checked with
// Lstat that path is a regular file when links must not be followed.
func openNonblocking(path string, _ bool) (*os.File, error) {
	return os.Open(path)
}

// openedOneName reports whether f is a folder or a file with one name.
func openedOneName(f *os.File) bool {
	conn, err := f.SyscallConn()
	if err != nil {
		return false
	}
	ok := false
	_ = conn.Control(func(fd uintptr) {
		var info windows.ByHandleFileInformation
		if windows.GetFileInformationByHandle(windows.Handle(fd), &info) == nil {
			ok = info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 || info.NumberOfLinks == 1
		}
	})
	return ok
}

// openedPath returns the final path Windows gives the opened handle.
func openedPath(f *os.File) (string, bool) {
	conn, err := f.SyscallConn()
	if err != nil {
		return "", false
	}
	var final string
	ok := false
	_ = conn.Control(func(fd uintptr) {
		buf := make([]uint16, windows.MAX_LONG_PATH)
		n, err := windows.GetFinalPathNameByHandle(windows.Handle(fd), &buf[0], uint32(len(buf)), 0) // FILE_NAME_NORMALIZED, VOLUME_NAME_DOS
		if err != nil || n == 0 || n >= uint32(len(buf)) {
			return
		}
		final = windows.UTF16ToString(buf[:n])
		if strings.HasPrefix(final, `\\?\UNC\`) {
			final = `\\` + final[len(`\\?\UNC\`):]
		} else {
			final = strings.TrimPrefix(final, `\\?\`)
		}
		ok = true
	})
	return final, ok
}

// resolvesToItself reports whether path, opened without following a final
// link, resolves to the same path. It needs read-attributes access on path
// alone, not on the folders above it; a link or junction anywhere above
// path makes the resolved path differ.
func resolvesToItself(path string) bool {
	ptr, err := winpath.UTF16Ptr(path)
	if err != nil {
		return false
	}
	handle, err := windows.CreateFile(ptr, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(handle)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetFinalPathNameByHandle(handle, &buf[0], uint32(len(buf)), 0) // FILE_NAME_NORMALIZED, VOLUME_NAME_DOS
	if err != nil || n == 0 || n >= uint32(len(buf)) {
		return false
	}
	final := strings.TrimPrefix(windows.UTF16ToString(buf[:n]), `\\?\`)
	return strings.EqualFold(filepath.Clean(final), filepath.Clean(path))
}
