//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// sfRestricted is SF_RESTRICTED: the object is protected by System Integrity
// Protection.
const sfRestricted = 0x00080000

// ClassifyDenial sorts a failed file operation on path. macOS returns EPERM
// for write-blocking flags, Endpoint Security and TCC denials and SIP alike,
// and EACCES for mode and ACL denials; Go merges both into os.IsPermission.
// Only DenialAccess is permission drift a re-stamp can fix. DenialFlags is
// fixed by clearing the flags; the other classes are prerequisites to report.
func ClassifyDenial(path string, err error) DenialClass {
	switch {
	case err == nil:
		return DenialNone
	case errors.Is(err, unix.EACCES):
		return DenialAccess
	case !errors.Is(err, unix.EPERM):
		return DenialOther
	}
	// Unlink, rename and create also fail when the parent folder carries a
	// write-blocking flag, so look at both.
	for _, candidate := range []string{path, filepath.Dir(path)} {
		var st unix.Stat_t
		if candidate == "" || unix.Lstat(candidate, &st) != nil {
			continue
		}
		if st.Flags&(darwinUserBlockingFlags|darwinSystemBlockingFlags) != 0 {
			return DenialFlags
		}
		if st.Flags&sfRestricted != 0 {
			return DenialSystemIntegrity
		}
	}
	return DenialPolicy
}

// darwinAdminMembers caches admin group membership per uid for the life of
// the process: an owner check runs on every guardian tick.
var darwinAdminMembers sync.Map

// darwinUIDIsAdmin reports whether uid is a member of the admin group, asked
// of Directory Services so nested and network groups count. A lookup that
// fails or times out answers false and is not cached, so a directory hiccup
// cannot pin a wrong answer.
func darwinUIDIsAdmin(uid uint32) bool {
	if uid == 0 {
		return true
	}
	if cached, ok := darwinAdminMembers.Load(uid); ok {
		return cached.(bool)
	}
	ctx, cancel := context.WithTimeout(context.Background(), darwinACLInspectionTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/dsmemberutil", "checkmembership", "-u", strconv.FormatUint(uint64(uid), 10), "-G", "admin")
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	member := strings.Contains(string(output), "is a member")
	darwinAdminMembers.Store(uid, member)
	return member
}
