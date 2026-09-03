// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"fmt"
	"strings"
	"os"
	"path/filepath"
	"syscall"
)

func validateDeviceIdentityPathSyntax(_, _ string) error { return nil }

func validateFreshIdentityDirectoryPlatform(path string, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("gateway: device identity directory ownership unavailable: %s", path)
	}
	if stat.Uid != uint32(os.Geteuid()) && !isContainerDeploymentMode() {
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

func syncFreshIdentityDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("gateway: open device identity directory %s for sync: %w", path, err)
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil {
		return fmt.Errorf("gateway: sync device identity directory %s: %w", path, syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("gateway: close device identity directory %s after sync: %w", path, closeErr)
	}
	return nil
}

func isContainerDeploymentMode() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("DEFENSECLAW_DEPLOYMENT_MODE")), "container")
}
