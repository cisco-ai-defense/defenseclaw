// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package watcher

import (
	"os"
	"syscall"
)

// ownedByAnotherAccount reports whether the folder at path belongs to an
// account other than the gateway's and root: the watcher creates no root
// below it (GAP-1251). Folders root owns keep the plain mkdir, which the file
// modes allow or refuse.
func ownedByAnotherAccount(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return stat.Uid != 0 && int64(stat.Uid) != int64(os.Geteuid())
}
