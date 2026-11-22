// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package effectrules

import (
	"os"
	"syscall"
)

// DiskIdentity reads a regular file's device, inode and link count. It runs
// on the resolver's answer, which already followed the links of the path, so
// os.Stat (not Lstat) is the identity of the file a write through the path
// changes: a symbolic link to a hard link of a member is that member too.
func DiskIdentity(path string) (FileID, bool) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return FileID{}, false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return FileID{}, false
	}
	return FileID{Dev: uint64(st.Dev), Ino: uint64(st.Ino), Links: uint64(st.Nlink)}, true //nolint:unconvert // Dev and Nlink widths differ by platform
}
