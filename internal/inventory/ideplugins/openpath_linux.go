// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ideplugins

import (
	"os"
	"strconv"
)

// openedPath returns the path the kernel gives the opened file in
// /proc/self/fd.
func openedPath(f *os.File) (string, bool) {
	conn, err := f.SyscallConn()
	if err != nil {
		return "", false
	}
	var path string
	ok := false
	_ = conn.Control(func(fd uintptr) {
		target, err := os.Readlink("/proc/self/fd/" + strconv.FormatUint(uint64(fd), 10))
		if err == nil && target != "" && target[0] == '/' {
			path, ok = target, true
		}
	})
	return path, ok
}
