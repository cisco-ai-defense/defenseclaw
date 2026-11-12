// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package daemon

import (
	"io/fs"
	"syscall"

	"golang.org/x/sys/unix"
)

// fileOwnerUID is the owning user of an lstat result.
func fileOwnerUID(info fs.FileInfo) (uint32, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint32(stat.Uid), true
}

// accountCanUseDir reports whether the calling account can enter and write
// the directory, as access(2) answers it.
func accountCanUseDir(path string) bool {
	return unix.Access(path, unix.W_OK|unix.X_OK) == nil
}
