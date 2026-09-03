// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package safefile

import (
	"fmt"
	"os"
	"strings"
)

func protectFile(_ string, file *os.File) error { return file.Chmod(0o600) }

func isContainerMode() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("DEFENSECLAW_DEPLOYMENT_MODE")), "container")
}

func protectDirectory(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o077 == 0 {
		return nil
	}
	return os.Chmod(path, 0o700)
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
	if isContainerMode() {
		return nil
	}
	if wantDirectory && info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("safefile: private directory permissions are too broad: %s", path)
	}
	if !wantDirectory && info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("safefile: private file permissions are too broad: %s", path)
	}
	return nil
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
