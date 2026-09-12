//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acp

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/windows"
)

func withEnterpriseCredentialMutationLock(dataDir string, fn func() error) error {
	lockPath, err := enterpriseCredentialLockPath(dataDir)
	if err != nil {
		return err
	}
	lockDir := filepath.Dir(lockPath)
	if err := managed.PrepareServiceRuntimeDir(
		managed.DeploymentModeManagedEnterprise, lockDir, "ACP enterprise credential lock directory",
	); err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(lockPath)
	if err != nil {
		return fmt.Errorf("encode ACP enterprise credential lock path: %w", err)
	}
	handle, err := windows.CreateFile(
		name,
		windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return fmt.Errorf("open ACP enterprise credential lock: %w", err)
	}
	file := os.NewFile(uintptr(handle), lockPath)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return fmt.Errorf("wrap ACP enterprise credential lock handle")
	}
	defer file.Close()
	if err := validateEnterpriseCredentialLockFile(lockPath, file, handle); err != nil {
		return err
	}
	overlapped := new(windows.Overlapped)
	if err := windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, overlapped); err != nil {
		return fmt.Errorf("acquire ACP enterprise credential lock: %w", err)
	}
	defer windows.UnlockFileEx(handle, 0, 1, 0, overlapped) //nolint:errcheck // close also releases the lock
	if err := validateEnterpriseCredentialLockFile(lockPath, file, handle); err != nil {
		return err
	}
	return fn()
}

func validateEnterpriseCredentialLockFile(path string, file *os.File, handle windows.Handle) error {
	if err := managed.ValidateTrustedServiceRuntimeFilePath(
		path, "ACP enterprise credential lock", os.Getenv(managed.WindowsServiceAccountEnv),
	); err != nil {
		return err
	}
	opened, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect ACP enterprise credential lock handle: %w", err)
	}
	named, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect ACP enterprise credential lock name: %w", err)
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return fmt.Errorf("inspect ACP enterprise credential lock identity: %w", err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.NumberOfLinks != 1 ||
		!opened.Mode().IsRegular() || !os.SameFile(opened, named) || opened.Size() != 0 {
		return fmt.Errorf("ACP enterprise credential lock is not a stable empty single-link regular file")
	}
	return nil
}
