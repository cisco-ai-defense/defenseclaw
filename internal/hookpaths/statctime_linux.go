// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookpaths

import (
	"os"
	"syscall"
	"time"
)

// statChangeTime is the inode change time of info: it moves on every write,
// rename, link and unlink of the entry and cannot be set back. ok is false
// where the platform does not report it.
func statChangeTime(info os.FileInfo) (time.Time, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(int64(stat.Ctim.Sec), int64(stat.Ctim.Nsec)), true
}
