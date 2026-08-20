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
	"strings"
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

// ValidateTrustedServiceRuntimeDir is the cross-platform service-runtime
// entry point. On unix the packaged defenseclaw account is resolved by
// username (via user.Lookup) inside trustedRuntimeOwner; the
// Windows-format `NT SERVICE\...` account name in the third argument
// cannot be reused for a unix user lookup, so it is intentionally
// dropped here. To point unix trust at a non-default username, set the
// DEFENSECLAW_UNIX_SERVICE_ACCOUNT env — trustedRuntimeOwner reads it
// on every check. When neither the env is set nor the "defenseclaw"
// user exists, the ancestor walk fails with a clear "owner uid N is
// not trusted" error instead of silently allowing any owner.
func ValidateTrustedServiceRuntimeDir(path, label, _ string) error {
	return ValidateTrustedRuntimeDir(path, label)
}

// ValidateTrustedServiceRuntimeFilePath validates a service-owned runtime
// file. The file itself may be owned by the packaged defenseclaw service
// account (WriteServiceRuntimeFile stages and renames as that user), so
// require ownership by root OR that trusted service uid — same rule as
// ValidateTrustedRuntimeDir applies to its ancestors. Config, manifests,
// and the authorization ledger keep the stricter root-only contract via
// ValidateTrustedFilePath.
func ValidateTrustedServiceRuntimeFilePath(path, label, _ string) error {
	if label == "" {
		label = "managed runtime file"
	}
	if path == "" {
		return fmt.Errorf("%s path is empty", label)
	}
	clean, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve %s path: %w", label, err)
	}
	if err := validateTrustedRuntimeFileElement(clean, label); err != nil {
		return err
	}
	for dir := filepath.Dir(clean); dir != filepath.Dir(dir); dir = filepath.Dir(dir) {
		if err := validateTrustedRuntimeDirElement(dir, label); err != nil {
			return err
		}
	}
	return validateTrustedRuntimeDirElement(filepath.VolumeName(clean)+string(filepath.Separator), label)
}

func validateTrustedRuntimeFileElement(path, label string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s: symlinks are not allowed in %s path", path, label)
	}
	if !info.Mode().IsRegular() {
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
	if !trustedRuntimeOwner(st.Uid) {
		return fmt.Errorf("%s: owner uid %d is not trusted for %s; expected root/admin uid 0 or defenseclaw service uid", path, st.Uid, label)
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
	// The unix trust model accepts root (uid 0) or the packaged
	// defenseclaw service account. The service account username is
	// "defenseclaw" by convention (installer contract). Setting
	// DEFENSECLAW_UNIX_SERVICE_ACCOUNT lets custom packaging point trust
	// at a different username without patching the source — the finder
	// audit flagged this as previously silently unavailable because the
	// serviceAccount parameter on ValidateTrustedServiceRuntimeDir is a
	// Windows-format `NT SERVICE\...` value and cannot be reused here.
	username := "defenseclaw"
	if custom := strings.TrimSpace(os.Getenv(UnixServiceAccountEnv)); custom != "" {
		username = custom
	}
	serviceUser, err := user.Lookup(username)
	if err != nil {
		return false
	}
	serviceUID, err := strconv.ParseUint(serviceUser.Uid, 10, 32)
	if err != nil {
		return false
	}
	return uid == uint32(serviceUID)
}
