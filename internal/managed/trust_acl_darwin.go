//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"fmt"
	"os/exec"
	"syscall"
)

// validateTrustedPathACL rejects effective macOS ACL entries that grant
// write-like authority beyond the POSIX owner/group/mode metadata validated by
// trust_unix.go. macOS keeps those mode bits unchanged when an ACL is added, so
// ignoring the extended entries would misclassify an attacker-writable path as
// administrator-trusted.
//
// Reading an ACL starts /bin/ls, and the managed gateway checks every element
// of its identity spool path on every hook call, so a burst of parallel tool
// calls spent its time starting ls processes (GAP-1822). A path whose ACL was
// read and found clean is therefore not read again while its inode metadata
// is unchanged: an ACL change, like any metadata change, sets the inode
// change time, and a replaced path has another inode.
func validateTrustedPathACL(path string) error {
	return darwinACLVerdicts.check(path, darwinACLStatKey, darwinACLInspect)
}

// darwinACLVerdicts holds the clean ACL verdicts of the process.
var darwinACLVerdicts aclVerdictCache

// darwinACLInspect reads the ACL of path (a variable for tests).
var darwinACLInspect = inspectDarwinACL

// darwinACLStatKey is the inode metadata a clean ACL verdict of path stays
// valid for.
func darwinACLStatKey(path string) (aclVerdictKey, error) {
	var st syscall.Stat_t
	if err := syscall.Lstat(path, &st); err != nil {
		return aclVerdictKey{}, err
	}
	return aclVerdictKey{
		path:  path,
		dev:   uint64(st.Dev),
		ino:   st.Ino,
		ctime: st.Ctimespec.Nano(),
		mode:  uint32(st.Mode),
		uid:   st.Uid,
		gid:   st.Gid,
	}, nil
}

func inspectDarwinACL(path string) error {
	cmd := exec.Command("/bin/ls", "-lde", "--", path)
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("inspect macOS ACL for %s: %w", path, err)
	}
	entries, err := ParseDarwinACLListing(string(output), []string{path})
	if err != nil {
		// Malformed `ls -lde` output is not a judgement about the permissions
		// themselves. Keep it a plain error so the ancestor downgrade cannot
		// swallow an ACL this code failed to read (see
		// relaxAncestorTrustJudgement).
		return fmt.Errorf("inspect macOS ACL: %w", err)
	}
	for _, entry := range entries[path] {
		if entry.GrantsWrite() {
			return newTrustVerdict("%s has write-capable macOS ACL entry", path)
		}
	}
	return nil
}
