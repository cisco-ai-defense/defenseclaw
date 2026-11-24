// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package inventory

import (
	"os"
	"syscall"
)

// skillHomeTrust is the trust for a skill folder in home.
func (s *ContinuousDiscoveryService) skillHomeTrust(home string) func(*os.File, string) bool {
	return skillHomeOwnerTrust(home)
}

// skillHomeOwnerTrust approves a folder a resolved skill path goes through
// when the owner of home (the scanning account when home is "") owns it, or
// root owns it and lets that owner search it. A link in a home therefore
// cannot lead a scan running as root into a folder such as /root. Below a
// linked skill folder the walk asks it about every file too (GAP-2008): a
// file the owner owns, or a root file others may read.
func skillHomeOwnerTrust(home string) func(*os.File, string) bool {
	owner := uint32(os.Geteuid())
	if home != "" {
		info, err := os.Stat(home)
		st, ok := skillStat(info, err)
		if !ok {
			return func(*os.File, string) bool { return false }
		}
		owner = st.Uid
	}
	return func(opened *os.File, _ string) bool {
		info, err := opened.Stat()
		st, ok := skillStat(info, err)
		if !ok {
			return false
		}
		var others os.FileMode // what root lets every account do
		switch {
		case info.IsDir():
			others = 0o001 // search
		case info.Mode().IsRegular():
			others = 0o004 // read
		default:
			return false
		}
		return st.Uid == owner || st.Uid == 0 && info.Mode().Perm()&others != 0
	}
}

func skillStat(info os.FileInfo, err error) (*syscall.Stat_t, bool) {
	if err != nil {
		return nil, false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return st, ok
}
