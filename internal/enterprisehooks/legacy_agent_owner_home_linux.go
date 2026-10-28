// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package enterprisehooks

import "golang.org/x/sys/unix"

// homeIdentity stats the directory home, following symlinks, and proves
// its device, inode and creation time are those of one object: the
// creation time comes from a statx of the same followed path, taken only
// when that statx names the same inode. The inode came from the followed
// home and the creation time from the symlink itself (AT_SYMLINK_NOFOLLOW),
// so a symlinked home recreated with a reused inode kept its proof, and the
// account that got the uid next inherited the earlier account's agent rows
// (GAP-0939). Without statx (an old kernel, or a sandbox that refuses it),
// or when the home is replaced between the two calls, the home is proven
// by device and inode alone, as on a file system that keeps no creation
// time.
func homeIdentity(home string) (homeProof, bool) {
	var st unix.Stat_t
	if err := unix.Stat(home, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return homeProof{}, false
	}
	proof := homeProof{dev: st.Dev, ino: st.Ino}
	var stx unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, home, 0, unix.STATX_INO|unix.STATX_BTIME, &stx); err == nil &&
		stx.Mask&(unix.STATX_INO|unix.STATX_BTIME) == unix.STATX_INO|unix.STATX_BTIME && stx.Ino == st.Ino &&
		unix.Mkdev(stx.Dev_major, stx.Dev_minor) == st.Dev {
		proof.birth, proof.hasBirth = stx.Btime.Sec*1_000_000_000+int64(stx.Btime.Nsec), true
	}
	return proof, true
}

// symlinkBirth is the creation time of home itself in nanoseconds when
// home is a symlink: the creation time the 1.0.4 builds before the GAP-0939
// fix put in the owner token of a symlinked home (LegacyAgentOwnerTokenFor).
// false when home is not a symlink, or its creation time is not known.
func symlinkBirth(home string) (int64, bool) {
	var stx unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, home, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_TYPE|unix.STATX_BTIME, &stx); err != nil ||
		stx.Mask&(unix.STATX_TYPE|unix.STATX_BTIME) != unix.STATX_TYPE|unix.STATX_BTIME || stx.Mode&unix.S_IFMT != unix.S_IFLNK {
		return 0, false
	}
	return stx.Btime.Sec*1_000_000_000 + int64(stx.Btime.Nsec), true
}
