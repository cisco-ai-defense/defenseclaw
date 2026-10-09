// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// The lock file remains in place after release: removing it could let a new
// setup lock a different inode while an existing waiter still holds the old one.
func openACPUserSetupLock(clientPath string, extraFlags int) (*os.File, error) {
	lockPath := clientPath + ".defenseclaw.lock"
	if err := safefile.ProtectDirectory(filepath.Dir(lockPath)); err != nil {
		return nil, fmt.Errorf("prepare ACP editor lock directory: %w", err)
	}
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR|extraFlags, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open ACP editor lock: %w", err)
	}
	if err := safefile.ProtectFile(lockPath); err != nil {
		file.Close()
		return nil, fmt.Errorf("protect ACP editor lock: %w", err)
	}
	if err := validateACPUserSetupLock(lockPath, file); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func validateACPUserSetupLock(path string, file *os.File) error {
	if err := safefile.ValidatePrivateFile(path); err != nil {
		return fmt.Errorf("validate ACP editor lock: %w", err)
	}
	opened, err := file.Stat()
	if err != nil {
		return err
	}
	named, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !opened.Mode().IsRegular() || !named.Mode().IsRegular() ||
		!os.SameFile(opened, named) || opened.Size() != 0 {
		return fmt.Errorf("ACP editor lock is not a stable empty regular file")
	}
	return nil
}
