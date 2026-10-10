// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// rulePackTreeMaxEntries bounds the walk of an administrator rule pack.
const rulePackTreeMaxEntries = 20000

var errRulePackTreeTooLarge = errors.New("too many entries")

// rulePackTrust is the TrustRulePack check. The pack folder and the folders
// above it pass the gateway's own check of a managed rule pack (no symlink,
// not writable by group or others, no ACL write entry, owned by root or the
// service account), so ensure refuses a pack before the gateway is
// restarted into a failed start (GAP-0546). Every folder and file in the
// pack is then owned by root, so a standard user who owns one file (a pack
// copied with cp -a) cannot change what every user's agents are held to
// (GAP-0552).
func rulePackTrust(dir string) error {
	if err := managed.ValidateTrustedRuntimeDir(dir, "rule pack"); err != nil {
		return err
	}
	return rulePackTreeTrust(dir, func(uid uint32) bool { return uid == 0 })
}

// rulePackTreeTrust walks the pack without following links: each entry must
// not be a symlink, writable by group or others or carry an ACL write
// entry, and must be owned by an account trustedOwner accepts.
func rulePackTreeTrust(dir string, trustedOwner func(uint32) bool) error {
	entries := 0
	err := filepath.WalkDir(dir, func(path string, _ fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entries++; entries > rulePackTreeMaxEntries {
			return errRulePackTreeTooLarge
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symlink; symlinks are not allowed in a rule pack", path)
		}
		if perm := info.Mode().Perm(); perm&0o022 != 0 {
			return fmt.Errorf("%s: group/other writable permissions %04o are not trusted", path, perm)
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("%s: cannot inspect the owner", path)
		}
		if !trustedOwner(st.Uid) {
			return fmt.Errorf("%s is owned by uid %d, not root", path, st.Uid)
		}
		return managed.ValidatePathACL(path)
	})
	if errors.Is(err, errRulePackTreeTooLarge) {
		return fmt.Errorf("%s has more than %d entries", dir, rulePackTreeMaxEntries)
	}
	return err
}

// rulePackTrustAdvice is the fix named with a refused pack.
const rulePackTrustAdvice = "keep every folder and file of the pack, and the folders above it, owned by root and not writable by group or others, without symlinks or ACL entries that grant write (for example: chown -R root:root <pack> && chmod -R go-w <pack>)"
