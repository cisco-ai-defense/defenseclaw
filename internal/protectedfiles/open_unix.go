// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package protectedfiles

import (
	"os"
	"path/filepath"
	"syscall"
)

// openNoFollow opens path for reading without following a final symlink
// and without blocking on a FIFO swapped in after the Lstat.
func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}

// restorableDefault allows a restore only where this process owns the
// directory (and the file, when it exists) and the directory is not a
// symlink: a per-user gateway restores its own user's files, and a gateway
// running as another account (a managed service) never writes into a
// user's home.
func restorableDefault(path string) bool {
	uid := uint32(os.Geteuid())
	owned := func(p string, wantDir bool) bool {
		info, err := os.Lstat(p)
		if err != nil {
			return false
		}
		if info.Mode()&os.ModeSymlink != 0 || info.IsDir() != wantDir {
			return false
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		return ok && st.Uid == uid
	}
	if !owned(filepath.Dir(path), true) {
		return false
	}
	if _, err := os.Lstat(path); err == nil && !owned(path, false) {
		return false
	}
	return true
}
