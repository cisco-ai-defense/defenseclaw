// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"os"
	"syscall"
)

func perUserHelperRestoreSupported() bool { return true }

// perUserPrivateDir: a real folder of this account that no other account can
// change (no group or other write).
func perUserPrivateDir(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() {
		return false
	}
	return perUserOwnedPrivateFile(info)
}

func perUserOwnedPrivateFile(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Getuid() {
		return false
	}
	return info.Mode().Perm()&0o022 == 0
}
