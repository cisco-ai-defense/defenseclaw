// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package kit

import (
	"fmt"
	"os"
	"syscall"
)

func rootOwned(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("actor kit config: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("actor kit config: %s is a symlink", path)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 {
		return fmt.Errorf("actor kit config: %s is not owned by root", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("actor kit config: %s is writable by group or others", path)
	}
	return nil
}

func fileOwner(info os.FileInfo) (uid, gid int, nlink uint64) {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid), int(st.Gid), uint64(st.Nlink)
	}
	return -1, -1, 0
}
