// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package assetfacts

import (
	"os"
	"path/filepath"
	"syscall"
)

// callerCanEnterDirectory proves search permission on every component for
// the peer's primary uid/gid. Supplementary groups and ACLs are not known to
// the gateway; an unproven path is checked along with the original cwd.
func callerCanEnterDirectory(path string, uid, gid int) bool {
	if uid < 0 || gid < 0 || !filepath.IsAbs(path) {
		return false
	}
	for dir := filepath.Clean(path); ; dir = filepath.Dir(dir) {
		info, err := fsStat(dir)
		if err != nil || !info.IsDir() {
			return false
		}
		// Mode bits do not establish the peer's search permission when an
		// access ACL may select a named user or group instead. An uncertain cd
		// leaves both the original and candidate trees in the policy check.
		if !directoryAccessACLAbsent(dir) {
			return false
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return false
		}
		mode := info.Mode().Perm()
		var search os.FileMode
		switch {
		case uid == 0:
			search = 0o111
		case uint32(uid) == stat.Uid:
			search = 0o100
		case uint32(gid) == stat.Gid:
			search = 0o010
		default:
			// A supplementary group may select the group bits instead of
			// the other-user bits. Both must permit search to prove entry.
			if mode&0o010 == 0 {
				return false
			}
			search = 0o001
		}
		if mode&search == 0 {
			return false
		}
		if parent := filepath.Dir(dir); parent == dir {
			return true
		}
	}
}
