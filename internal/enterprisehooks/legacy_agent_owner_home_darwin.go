// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package enterprisehooks

import "syscall"

// homeIdentity stats the directory home, following symlinks, in one stat
// call, so its device, inode and creation time are those of one object.
// The inode came from the followed home and the creation time from the
// symlink itself (Lstat), so a symlinked home recreated with a reused inode
// kept its proof (GAP-0939).
func homeIdentity(home string) (homeProof, bool) {
	var st syscall.Stat_t
	if err := syscall.Stat(home, &st); err != nil || st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return homeProof{}, false
	}
	proof := homeProof{dev: uint64(st.Dev), ino: st.Ino}
	if st.Birthtimespec.Sec != 0 || st.Birthtimespec.Nsec != 0 {
		proof.birth, proof.hasBirth = st.Birthtimespec.Sec*1_000_000_000+st.Birthtimespec.Nsec, true
	}
	return proof, true
}
