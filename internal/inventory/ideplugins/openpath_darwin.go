// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package ideplugins

import (
	"bytes"
	"os"
	"syscall"
	"unsafe"
)

// fGetPath is F_GETPATH, which gives an open file's current path (at most
// MAXPATHLEN bytes).
const fGetPath = 0x32

// openedPath returns the path the kernel gives the opened file (F_GETPATH):
// the folders on the way are the real ones, as with /proc/self/fd on Linux.
func openedPath(f *os.File) (string, bool) {
	conn, err := f.SyscallConn()
	if err != nil {
		return "", false
	}
	var path string
	ok := false
	_ = conn.Control(func(fd uintptr) {
		var buf [1024]byte
		if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, fGetPath, uintptr(unsafe.Pointer(&buf[0]))); errno != 0 {
			return
		}
		if n := bytes.IndexByte(buf[:], 0); n > 0 && buf[0] == '/' {
			path, ok = string(buf[:n]), true
		}
	})
	return path, ok
}
