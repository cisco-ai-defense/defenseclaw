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
	"path/filepath"
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
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: cannot inspect file owner", path)
	}
	if st.Uid != 0 {
		return fmt.Errorf("%s: owner uid %d is not trusted for %s; expected root/admin uid 0", path, st.Uid, label)
	}
	return nil
}
