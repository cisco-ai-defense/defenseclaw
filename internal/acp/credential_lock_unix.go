//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acp

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// withEnterpriseCredentialMutationLock keeps the record and bearer-derived
// index transaction exclusive across gateway, CLI, and installer processes.
// The inode is persistent: unlinking it after unlock could let waiters lock an
// orphan while a later process locks a newly created file at the same path.
func withEnterpriseCredentialMutationLock(dataDir string, fn func() error) error {
	lockPath, err := enterpriseCredentialLockPath(dataDir)
	if err != nil {
		return err
	}
	lockDir := filepath.Dir(lockPath)
	if err := safefile.ProtectDirectory(lockDir); err != nil {
		return fmt.Errorf("prepare ACP enterprise credential lock directory: %w", err)
	}
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("open ACP enterprise credential lock: %w", err)
	}
	defer file.Close()
	if err := validateEnterpriseCredentialLockFile(lockPath, file); err != nil {
		return err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("acquire ACP enterprise credential lock: %w", err)
	}
	defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN) //nolint:errcheck // close also releases the lock
	if err := validateEnterpriseCredentialLockFile(lockPath, file); err != nil {
		return err
	}
	return fn()
}

func validateEnterpriseCredentialLockFile(path string, file *os.File) error {
	if err := safefile.ValidatePrivateFile(path); err != nil {
		return fmt.Errorf("validate ACP enterprise credential lock: %w", err)
	}
	opened, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect ACP enterprise credential lock handle: %w", err)
	}
	named, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect ACP enterprise credential lock name: %w", err)
	}
	if !opened.Mode().IsRegular() || !os.SameFile(opened, named) || opened.Size() != 0 {
		return fmt.Errorf("ACP enterprise credential lock is not a stable empty regular file")
	}
	if stat, ok := opened.Sys().(*syscall.Stat_t); !ok || stat.Nlink != 1 {
		return fmt.Errorf("ACP enterprise credential lock must have exactly one link")
	}
	return nil
}
