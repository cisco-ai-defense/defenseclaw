// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package ideplugins

import (
	"os"
	"strconv"
)

// openedOneName reports whether f has one name. Unix scans of another
// account's home run with protected hard links (Linux) or as that account
// (the per-user scan), so they do not check it.
func openedOneName(*os.File) bool { return true }

// openedPath returns the path the kernel gives the opened file in
// /proc/self/fd. A system without procfs (macOS) names none.
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
