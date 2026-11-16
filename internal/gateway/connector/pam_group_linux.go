// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package connector

import (
	"os"
	"path/filepath"
	"strings"
)

// Where the PAM stack is configured (tests point them elsewhere).
var (
	privateGroupPAMStackDirs = []string{"/etc/pam.d", "/usr/lib/pam.d", "/usr/share/pam.d"}
	privateGroupPAMConfFile  = "/etc/pam.conf"
)

const privateGroupPAMStackMaxBytes = 1 << 20

// pamGroupLoaded reports whether any PAM stack file loads pam_group, the module
// that adds an account to a group at login by rules in group.conf and
// group.d. It asks only whether the module is loaded, never what the rules say
// or where the module reads them from: the answer is a line, outside a
// comment, that names pam_group in a file of the stack directories or in
// pam.conf. Where it is loaded, an account the private-group proof does not
// list can still gain the group, so a caller watches the folder instead of
// trusting it (GAP-0905). A stack file or directory that cannot be read, a link
// that does not resolve, an oversize file or a file that is no regular file
// counts as loaded. Links are followed as the PAM library follows them.
func pamGroupLoaded() bool {
	for _, dir := range privateGroupPAMStackDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return true
		}
		for _, entry := range entries {
			if pamStackFileLoadsGroup(filepath.Join(dir, entry.Name()), true) {
				return true
			}
		}
	}
	return pamStackFileLoadsGroup(privateGroupPAMConfFile, false)
}

// pamStackFileLoadsGroup reads one stack file. A file that is not there counts
// as loading nothing only when it was not listed by a directory read.
func pamStackFileLoadsGroup(path string, listed bool) bool {
	info, err := os.Lstat(path)
	if err != nil {
		return listed || !os.IsNotExist(err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		if info, err = os.Stat(path); err != nil {
			return true
		}
	}
	if info.IsDir() {
		return false
	}
	if !info.Mode().IsRegular() || info.Size() > privateGroupPAMStackMaxBytes {
		return true
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return true
	}
	for _, line := range strings.Split(string(data), "\n") {
		line, _, _ = strings.Cut(line, "#")
		if strings.Contains(line, "pam_group") {
			return true
		}
	}
	return false
}
