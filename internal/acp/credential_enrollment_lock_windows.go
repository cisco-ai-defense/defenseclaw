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

// AcquireEnterpriseCredentialEnrollmentLock keeps the service credential,
// user copy and failure cleanup exclusive across administrator processes.
func AcquireEnterpriseCredentialEnrollmentLock(dataDir string) (func(), error) {
	enterpriseCredentialEnrollmentMu.Lock()
	fail := func(err error) (func(), error) {
		enterpriseCredentialEnrollmentMu.Unlock()
		return nil, err
	}
	path, err := enterpriseCredentialEnrollmentLockPath(dataDir)
	if err != nil {
		return fail(err)
	}
	if err := managed.PrepareServiceRuntimeDir(
		managed.DeploymentModeManagedEnterprise, filepath.Dir(path), "ACP enrollment lock directory",
	); err != nil {
		return fail(err)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fail(err)
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return fail(fmt.Errorf("open ACP enrollment lock: %w", err))
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return fail(fmt.Errorf("wrap ACP enrollment lock handle"))
	}
	if err := validateEnterpriseCredentialLockFile(path, file, handle); err != nil {
		_ = file.Close()
		return fail(err)
	}
	overlapped := new(windows.Overlapped)
	if err := windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, overlapped); err != nil {
		_ = file.Close()
		return fail(fmt.Errorf("acquire ACP enrollment lock: %w", err))
	}
	if err := validateEnterpriseCredentialLockFile(path, file, handle); err != nil {
		_ = windows.UnlockFileEx(handle, 0, 1, 0, overlapped)
		_ = file.Close()
		return fail(err)
	}
	return func() {
		_ = windows.UnlockFileEx(handle, 0, 1, 0, overlapped)
		_ = file.Close()
		enterpriseCredentialEnrollmentMu.Unlock()
	}, nil
}
