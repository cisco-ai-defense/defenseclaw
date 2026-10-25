// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"os"
	"syscall"
)

// linkCount returns the number of hard links to a file. An unknown count is
// reported as more than one so the caller fails closed.
func linkCount(_ string, info os.FileInfo) uint64 {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(stat.Nlink)
	}
	return 2
}
