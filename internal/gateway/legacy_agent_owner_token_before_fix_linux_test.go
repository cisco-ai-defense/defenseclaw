// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gateway

import (
	"os"
	"strconv"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// ownerTokenBeforeSymlinkFix is the owner token of home as the 1.0.4 builds
// before the GAP-0939 fix computed it: the device and inode from a stat
// that follows a symlink, the creation time from a statx of home itself (AT_SYMLINK_NOFOLLOW).
func ownerTokenBeforeSymlinkFix(t *testing.T, home string) string {
	t.Helper()
	info, err := os.Stat(home)
	if err != nil {
		t.Fatal(err)
	}
	st := info.Sys().(*syscall.Stat_t)
	token := "home:" + strconv.FormatUint(uint64(st.Dev), 10) + ":" + strconv.FormatUint(uint64(st.Ino), 10)
	var stx unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, home, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_BTIME, &stx); err == nil && stx.Mask&unix.STATX_BTIME != 0 {
		token += ":" + strconv.FormatInt(stx.Btime.Sec*1_000_000_000+int64(stx.Btime.Nsec), 10)
	}
	return token
}
