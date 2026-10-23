//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"fmt"
	"os/exec"

	"golang.org/x/sys/unix"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// publishedSessionVolumeIsReadOnly reports a path on a volume mounted
// read-only (statfs MNT_RDONLY).
func publishedSessionVolumeIsReadOnly(path string) (bool, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return false, err
	}
	return st.Flags&unix.MNT_RDONLY != 0, nil
}

// publishedSessionFolderIsLocked reports a folder with a flag that keeps
// its owner from adding or removing a file (uchg, uappnd, schg, sappnd, or
// restricted), or an ACL deny entry for such a change: macOS checks a deny
// entry before the mode bits, and this check cannot tell whom a group entry
// covers, so any one counts.
func publishedSessionFolderIsLocked(path string) (bool, error) {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return false, err
	}
	const locked = unix.UF_IMMUTABLE | unix.UF_APPEND | unix.SF_IMMUTABLE | unix.SF_APPEND | unix.SF_RESTRICTED
	if st.Flags&locked != 0 {
		return true, nil
	}
	cmd := exec.Command("/bin/ls", "-lde", "--", path)
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	output, err := cmd.Output()
	if err != nil {
		return false, fmt.Errorf("inspect the macOS ACL of %s: %w", path, err)
	}
	entries, err := managed.ParseDarwinACLListing(string(output), []string{path})
	if err != nil {
		return false, err
	}
	for _, entry := range entries[path] {
		if publishedSessionACLDeniesChange(entry) {
			return true, nil
		}
	}
	return false, nil
}

// publishedSessionACLDeniesChange reports a deny entry that applies to the
// folder itself and refuses adding or removing a file in it.
func publishedSessionACLDeniesChange(entry managed.DarwinACLEntry) bool {
	if entry.Allow {
		return false
	}
	denies := false
	for _, right := range entry.Rights {
		switch right {
		case "only_inherit":
			return false
		case "add_file", "add_subdirectory", "delete_child", "write", "append":
			denies = true
		}
	}
	return denies
}
