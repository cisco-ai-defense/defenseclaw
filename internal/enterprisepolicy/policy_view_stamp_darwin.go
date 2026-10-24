// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package enterprisepolicy

import (
	"os"
	"strconv"
	"syscall"
)

// fileChangeStamp is the file's inode and change time. A content or
// metadata write always moves the change time, and no unprivileged call can
// set it back (PolicyViewStamp).
func fileChangeStamp(info os.FileInfo) string {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	return strconv.FormatUint(uint64(st.Ino), 10) + " " + strconv.FormatInt(st.Ctimespec.Sec, 10) + "." + strconv.FormatInt(st.Ctimespec.Nsec, 10)
}
