// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"os"
	"syscall"
)

// actionProcessOwnsHome reports a process that runs as the owner of home,
// so a directory it cannot list is one the user's shell cannot list either.
func actionProcessOwnsHome(home string) bool {
	info, err := pathStat(home)
	if err != nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Getuid()
}

// actionGlobDirDeniesEveryoneList is false off Windows: a POSIX mode has no
// deny entry for every account.
func actionGlobDirDeniesEveryoneList(string) bool { return false }
