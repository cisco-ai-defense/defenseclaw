// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func validateDeviceIdentityPathSyntax(_, _ string) error { return nil }

func validateFreshIdentityDirectoryPlatform(path string, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("gateway: device identity directory is not owned by the current user: %s", path)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("gateway: resolve device identity directory %s: %w", path, err)
	}
	if filepath.Clean(resolved) != filepath.Clean(path) {
		return fmt.Errorf("gateway: device identity directory path is indirect: %s", path)
	}
	return validateFreshIdentityPathACL(path)
}

func validateFreshIdentityFilePlatform(path string) error {
	return validateFreshIdentityPathACL(path)
}
