// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package gateway

import (
	"os"
	"strconv"
	"syscall"
	"testing"
)

// ownerTokenBeforeSymlinkFix is the owner token of home as the 1.0.4 builds
// before the GAP-0939 fix computed it: the device and inode from a stat
// that follows a symlink, the creation time from an Lstat of home itself.
func ownerTokenBeforeSymlinkFix(t *testing.T, home string) string {
	t.Helper()
	info, err := os.Stat(home)
	if err != nil {
		t.Fatal(err)
	}
	st := info.Sys().(*syscall.Stat_t)
	token := "home:" + strconv.FormatUint(uint64(st.Dev), 10) + ":" + strconv.FormatUint(uint64(st.Ino), 10)
	var lst syscall.Stat_t
	if err := syscall.Lstat(home, &lst); err == nil && (lst.Birthtimespec.Sec != 0 || lst.Birthtimespec.Nsec != 0) {
		token += ":" + strconv.FormatInt(lst.Birthtimespec.Sec*1_000_000_000+lst.Birthtimespec.Nsec, 10)
	}
	return token
}
