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

// homeIdentity stats the directory home, following symlinks, in one statx
// call, so its device, inode and creation time are those of one object.
// The inode came from the followed home and the creation time from the
// symlink itself (AT_SYMLINK_NOFOLLOW), so a symlinked home recreated with
// a reused inode kept its proof, and the account that got the uid next
// inherited the earlier account's agent rows (GAP-0939). Without statx
// (an old kernel, or a sandbox that refuses it) the home is proven by
// device and inode alone.
func homeIdentity(home string) (homeProof, bool) {
	const need = unix.STATX_TYPE | unix.STATX_INO
	var stx unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, home, 0, need|unix.STATX_BTIME, &stx); err == nil && stx.Mask&need == need {
		if uint32(stx.Mode)&unix.S_IFMT != unix.S_IFDIR {
			return homeProof{}, false
		}
		proof := homeProof{dev: unix.Mkdev(stx.Dev_major, stx.Dev_minor), ino: stx.Ino}
		if stx.Mask&unix.STATX_BTIME != 0 {
			proof.birth, proof.hasBirth = stx.Btime.Sec*1_000_000_000+int64(stx.Btime.Nsec), true
		}
		return proof, true
	}
	var st unix.Stat_t
	if err := unix.Stat(home, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return homeProof{}, false
	}
	return homeProof{dev: uint64(st.Dev), ino: st.Ino}, true
}
