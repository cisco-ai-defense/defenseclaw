// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func withOTLPPathTokenLock(path string, fn func() error) error {
	return withOwnedFileLock(path+".lock", fn)
}

func withOwnedFileLock(lockPath string, fn func() error) error {
	if err := hookAPIValidateDirectory(filepath.Dir(lockPath)); err != nil {
		return fmt.Errorf("validate DefenseClaw lock directory: %w", err)
	}
	if _, err := os.Lstat(lockPath); err == nil {
		if _, err := otlpWindowsPathSecurity(lockPath); err != nil {
			return fmt.Errorf("validate DefenseClaw lock path: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect DefenseClaw lock path: %w", err)
	}
	shareMode := uint32(windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE)
	file, err := openSecureOTLPWindowsFile(lockPath, windows.CREATE_NEW, shareMode, true)
	if errors.Is(err, windows.ERROR_FILE_EXISTS) || errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		file, err = openSecureOTLPWindowsFile(lockPath, windows.OPEN_EXISTING, shareMode, false)
	}
	if err != nil {
		return fmt.Errorf("open DefenseClaw lock: %w", err)
	}
	defer file.Close()
	if err := validateOwnedLockFile(lockPath, file); err != nil {
		return err
	}
	handle := windows.Handle(file.Fd())
	overlapped := new(windows.Overlapped)
	if err := windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, overlapped); err != nil {
		return fmt.Errorf("acquire DefenseClaw lock: %w", err)
	}
	defer windows.UnlockFileEx(handle, 0, 1, 0, overlapped) //nolint:errcheck // best-effort unlock on close
	return fn()
}
