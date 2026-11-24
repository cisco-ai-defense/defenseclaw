// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package inventory

import (
	"os"
	"syscall"
)

// skillHomeOwnerTrust approves a folder a resolved skill path goes through
// when the owner of home (the scanning account when home is "") owns it, or
// root owns it and lets that owner search it. A link in a home therefore
// cannot lead a scan running as root into a folder such as /root.
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
	return func(dir *os.File, _ string) bool {
		info, err := dir.Stat()
		st, ok := skillStat(info, err)
		if !ok || !info.IsDir() {
			return false
		}
		return st.Uid == owner || st.Uid == 0 && info.Mode().Perm()&0o001 != 0
	}
}

func skillStat(info os.FileInfo, err error) (*syscall.Stat_t, bool) {
	if err != nil {
		return nil, false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return st, ok
}
