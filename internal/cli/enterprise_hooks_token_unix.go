// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func validateEnterpriseHookScopedTokenLocation(dataDir, connectorName string) error {
	if _, err := validateEnterpriseHookManagedDir(dataDir, "managed data_dir", true); err != nil {
		return err
	}
	tokenPath, err := connector.HookAPITokenFilePath(dataDir, connectorName)
	if err != nil {
		return err
	}
	tokenDir := filepath.Dir(tokenPath)
	if _, err := validateEnterpriseHookManagedDir(tokenDir, "hook token dir", false); err != nil {
		return err
	}
	if info, err := os.Lstat(tokenPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("enterprise hooks: refusing symlink hook token: %s", tokenPath)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("enterprise hooks: hook token is not a regular file: %s", tokenPath)
		}
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("enterprise hooks: inspect hook token %s: %w", tokenPath, err)
	}
	return nil
}

func alignEnterpriseHookScopedTokenOwner(dataDir, connectorName string) error {
	info, err := validateEnterpriseHookManagedDir(dataDir, "managed data_dir", true)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("enterprise hooks: cannot inspect managed data_dir owner")
	}
	uid, gid := int(st.Uid), int(st.Gid)
	tokenPath, err := connector.HookAPITokenFilePath(dataDir, connectorName)
	if err != nil {
		return err
	}
	tokenDir := filepath.Dir(tokenPath)
	if _, err := validateEnterpriseHookManagedDir(tokenDir, "hook token dir", true); err != nil {
		return err
	}
	tokenInfo, err := os.Lstat(tokenPath)
	if err != nil {
		return fmt.Errorf("enterprise hooks: inspect hook token %s: %w", tokenPath, err)
	}
	if tokenInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("enterprise hooks: refusing symlink hook token: %s", tokenPath)
	}
	if !tokenInfo.Mode().IsRegular() {
		return fmt.Errorf("enterprise hooks: hook token is not a regular file: %s", tokenPath)
	}
	if os.Geteuid() == 0 {
		if err := os.Lchown(tokenDir, uid, gid); err != nil {
			return fmt.Errorf("enterprise hooks: lchown hook token dir: %w", err)
		}
		if err := os.Lchown(tokenPath, uid, gid); err != nil {
			return fmt.Errorf("enterprise hooks: lchown hook token: %w", err)
		}
	}
	if err := os.Chmod(tokenPath, 0o600); err != nil {
		return fmt.Errorf("enterprise hooks: chmod hook token: %w", err)
	}
	return nil
}

func validateEnterpriseHookManagedDir(path, label string, requireExisting bool) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) && !requireExisting {
			return nil, nil
		}
		return nil, fmt.Errorf("enterprise hooks: inspect %s %s: %w", label, path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("enterprise hooks: refusing symlink %s: %s", label, path)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("enterprise hooks: %s is not a directory: %s", label, path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("enterprise hooks: %s %s is group/other writable", label, path)
	}
	return info, nil
}
