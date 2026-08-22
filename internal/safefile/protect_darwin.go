// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package safefile

import (
	"fmt"
	"os"
)

func protectFile(path string, file *os.File) error {
	expected, err := file.Stat()
	if err != nil {
		return err
	}
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	return protectPrivateACL(path, expected)
}

func protectDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("safefile: private directory path has an unexpected type: %s", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(path, 0o700); err != nil {
			return err
		}
	}
	return protectPrivateACL(path, info)
}

func validatePrivateProtection(path string, wantDirectory bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || (wantDirectory && !info.IsDir()) ||
		(!wantDirectory && !info.Mode().IsRegular()) {
		return fmt.Errorf("safefile: private path has an unexpected type: %s", path)
	}
	if wantDirectory && info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("safefile: private directory permissions are too broad: %s", path)
	}
	if !wantDirectory && info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("safefile: private file permissions are too broad: %s", path)
	}
	return validatePrivateACL(path, info)
}

func rejectReparsePath(_ string) error { return nil }

func rejectReparseChain(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err == nil && info.Mode()&os.ModeSymlink != 0 {
		return ErrSymlinkRefused
	}
	return err
}

func preserveExistingProtection(_, _ string) error { return nil }

func withLockedDirectory(_ string, write func() error) error { return write() }

func makePrivateDirectories(path string) error { return os.MkdirAll(path, 0o700) }
