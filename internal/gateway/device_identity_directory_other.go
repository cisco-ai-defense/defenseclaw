// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/runtimeowner"
)

func validateDeviceIdentityPathSyntax(_, _ string) error { return nil }

func validateFreshIdentityDirectoryPlatform(path string, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("gateway: device identity directory is not owned by the current user: %s", path)
	}
	if !runtimeowner.Trusted(stat.Uid) {
		return fmt.Errorf("gateway: device identity directory is not owned by the current user: %s", path)
	}
	if stat.Uid == 0 && os.Geteuid() != 0 {
		return fmt.Errorf("gateway: device identity directory is root-owned from a sudo-started gateway: %s", path)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("gateway: resolve device identity directory %s: %w", path, err)
	}
	if filepath.Clean(resolved) != filepath.Clean(path) && !onlyRootAliasesInPath(path) {
		return fmt.Errorf("gateway: device identity directory path is indirect: %s", path)
	}
	return validateFreshIdentityPathACL(path)
}

// onlyRootAliasesInPath reports a path whose every symlink is a directory
// alias only root can replace: root-owned, at the top level or inside a
// root-owned directory no group or other account can write. An
// administrator's linked homes (/home/team -> /srv/team, GAP-1725, GAP-2078)
// are such aliases; the audit store trusts the same ones
// (trustedAuditDBSystemDirectoryAlias). Any other symlink makes the path
// indirect.
func onlyRootAliasesInPath(path string) bool {
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) {
		return false
	}
	current := string(os.PathSeparator)
	for _, part := range strings.Split(strings.TrimPrefix(path, current), string(os.PathSeparator)) {
		parent := current
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return false
		}
		if info.Mode()&os.ModeSymlink == 0 {
			continue
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return false
		}
		if parent != string(os.PathSeparator) {
			dir, err := os.Stat(parent)
			if err != nil || !dir.IsDir() {
				return false
			}
			owner, ok := dir.Sys().(*syscall.Stat_t)
			if !ok || owner.Uid != 0 || dir.Mode().Perm()&0o022 != 0 {
				return false
			}
		}
		target, err := os.Stat(current)
		if err != nil || !target.IsDir() {
			return false
		}
	}
	return true
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

// validateFreshIdentityManagedServiceDirectory has no managed exception
// off Windows: the unix standalone gateway owns its data directory.
func validateFreshIdentityManagedServiceDirectory(string) (bool, error) { return false, nil }

// writeFreshIdentityManagedServiceFile has no managed exception off Windows.
func writeFreshIdentityManagedServiceFile(string, []byte) (bool, error) { return false, nil }
