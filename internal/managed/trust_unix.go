//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
)

// ValidateTrustedConfigPath rejects managed_enterprise config paths that a
// standard user could replace or edit. The managed service may run as a
// dedicated non-root user, but the authoritative config must stay admin-owned.
func ValidateTrustedConfigPath(path string) error {
	return ValidateTrustedFilePath(path, "managed config")
}

// ValidateTrustedFilePath rejects managed_enterprise policy/input files that a
// standard user could replace or edit. The managed service may run as a
// dedicated non-root user, but authoritative inputs must stay admin-owned.
func ValidateTrustedFilePath(path, label string) error {
	if label == "" {
		label = "managed file"
	}
	if path == "" {
		return fmt.Errorf("%s path is empty", label)
	}
	clean, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve %s path: %w", label, err)
	}
	if err := validateTrustedPathElement(clean, false, label); err != nil {
		return err
	}
	for dir := filepath.Dir(clean); dir != filepath.Dir(dir); dir = filepath.Dir(dir) {
		if err := validateTrustedPathElement(dir, true, label); err != nil {
			return err
		}
	}
	return validateTrustedPathElement(filepath.VolumeName(clean)+string(filepath.Separator), true, label)
}

// ValidateTrustedRuntimeDir rejects managed_enterprise runtime directories that
// a standard user could replace or edit. Unlike authoritative config and
// manifest files, runtime state may be owned by the packaged DefenseClaw
// service account, but every path element still has to be non-symlink,
// non-writable by group/other, and owned by root or that service account.
func ValidateTrustedRuntimeDir(path, label string) error {
	if label == "" {
		label = "managed runtime dir"
	}
	if path == "" {
		return fmt.Errorf("%s path is empty", label)
	}
	clean, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve %s path: %w", label, err)
	}
	for cur := clean; ; cur = filepath.Dir(cur) {
		if err := validateTrustedRuntimeDirElement(cur, label); err != nil {
			return err
		}
		if cur == filepath.Dir(cur) {
			break
		}
	}
	return nil
}

func validateTrustedPathElement(path string, wantDir bool, label string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s: symlinks are not allowed in %s path", path, label)
	}
	if wantDir && !info.IsDir() {
		return fmt.Errorf("%s: expected directory in %s path", path, label)
	}
	if !wantDir && !info.Mode().IsRegular() {
		return fmt.Errorf("%s: expected regular %s file", path, label)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s: group/other writable permissions %04o are not trusted", path, info.Mode().Perm())
	}
	if err := validateTrustedPathACL(path); err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: cannot inspect file owner", path)
	}
	if st.Uid != 0 {
		return fmt.Errorf("%s: owner uid %d is not trusted for %s; expected root/admin uid 0", path, st.Uid, label)
	}
	return nil
}

func validateTrustedRuntimeDirElement(path string, label string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s: symlinks are not allowed in %s path", path, label)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s: expected directory in %s path", path, label)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s: group/other writable permissions %04o are not trusted", path, info.Mode().Perm())
	}
	if err := validateTrustedPathACL(path); err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: cannot inspect directory owner", path)
	}
	if !trustedRuntimeOwner(st.Uid) {
		return fmt.Errorf("%s: owner uid %d is not trusted for %s; expected root/admin uid 0 or defenseclaw service uid", path, st.Uid, label)
	}
	return nil
}

func trustedRuntimeOwner(uid uint32) bool {
	if uid == 0 {
		return true
	}
	serviceUser, err := user.Lookup("defenseclaw")
	if err != nil {
		return false
	}
	serviceUID, err := strconv.ParseUint(serviceUser.Uid, 10, 32)
	if err != nil {
		return false
	}
	return uid == uint32(serviceUID)
}
