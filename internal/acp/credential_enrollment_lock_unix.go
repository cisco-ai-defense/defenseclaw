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

// AcquireEnterpriseCredentialEnrollmentLock serializes enrollment through
// publication and rollback across CLI processes. The caller acquires it as
// the service owner, then may restore administrator privileges before writing
// the target user's copy. The persistent inode is never unlinked.
func AcquireEnterpriseCredentialEnrollmentLock(dataDir string) (func(), error) {
	enterpriseCredentialEnrollmentMu.Lock()
	path, err := enterpriseCredentialEnrollmentLockPath(dataDir)
	if err != nil {
		enterpriseCredentialEnrollmentMu.Unlock()
		return nil, err
	}
	if err := safefile.ProtectDirectory(filepath.Dir(path)); err != nil {
		enterpriseCredentialEnrollmentMu.Unlock()
		return nil, fmt.Errorf("prepare ACP enrollment lock directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		enterpriseCredentialEnrollmentMu.Unlock()
		return nil, fmt.Errorf("open ACP enrollment lock: %w", err)
	}
	if err := validateEnterpriseCredentialLockFile(path, file); err != nil {
		file.Close()
		enterpriseCredentialEnrollmentMu.Unlock()
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		file.Close()
		enterpriseCredentialEnrollmentMu.Unlock()
		return nil, fmt.Errorf("acquire ACP enrollment lock: %w", err)
	}
	if err := validateEnterpriseCredentialLockFile(path, file); err != nil {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		file.Close()
		enterpriseCredentialEnrollmentMu.Unlock()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
		enterpriseCredentialEnrollmentMu.Unlock()
	}, nil
}
