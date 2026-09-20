// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"os"
	"syscall"
)

// fileOwner returns the uid/gid of the file described by info, or -1
// on any platform / stat-type mismatch. Used by writeConfigAtomic to
// preserve the user's ownership across a `sudo uninstall.sh` scrub.
func fileOwner(info os.FileInfo) (int, int) {
	if info == nil {
		return -1, -1
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return -1, -1
	}
	return int(st.Uid), int(st.Gid)
}
