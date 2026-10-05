// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func validateDeviceIdentityPathSyntax(target, dataDir string) error {
	for _, path := range []string{target, dataDir} {
		volume := filepath.VolumeName(path)
		if strings.Contains(path[len(volume):], ":") {
			return fmt.Errorf("gateway: device identity paths cannot use Windows alternate data streams")
		}
	}
	return nil
}

// Windows path ownership and full-chain reparse checks are enforced by
// safefile.ValidatePrivateDirectory immediately after this platform hook.
func validateFreshIdentityDirectoryPlatform(_ string, _ os.FileInfo) error { return nil }

func validateFreshIdentityFilePlatform(string) error { return nil }

// Windows does not support fsync on an opened directory handle. The file
// handle itself is flushed before this hook is reached.
func syncFreshIdentityDirectory(string) error { return nil }

// validateFreshIdentityManagedServiceDirectory validates the device identity
// directory of the standalone managed gateway service. Its runtime tree is
// Administrators-owned with a writer ACE for the exact NT SERVICE account, so
// the per-user private-directory contract (sole ownership by the caller) can
// never hold there; the managed service trust model is the equivalent check.
// Only the standalone profile pin selects it.
func validateFreshIdentityManagedServiceDirectory(path string) (bool, error) {
	account, ok := standaloneManagedServiceAccount()
	if !ok {
		return false, nil
	}
	if err := managed.ValidateTrustedServiceRuntimeDir(path, "device identity directory", account); err != nil {
		return true, fmt.Errorf("gateway: validate managed device identity directory %s: %w", path, err)
	}
	return true, nil
}

// writeFreshIdentityManagedServiceFile publishes a device identity artifact
// for the standalone managed gateway service. A private DACL (the service SID
// and SYSTEM only) would lock Administrators out of the runtime tree that the
// lifecycle snapshots, restores and re-ACLs during upgrade and repair, so the
// file is created exclusively under the inherited runtime DACL of its
// directory (SYSTEM and Administrators full, the service SID read and write,
// nobody else) and then validated with the managed service trust model.
func writeFreshIdentityManagedServiceFile(path string, data []byte) (bool, error) {
	account, ok := standaloneManagedServiceAccount()
	if !ok {
		return false, nil
	}
	if err := managed.ValidateTrustedServiceRuntimeDir(filepath.Dir(path), "device identity directory", account); err != nil {
		return true, fmt.Errorf("gateway: validate managed device identity directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return true, fmt.Errorf("gateway: create managed device identity artifact %s: %w", path, err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return true, err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return true, err
	}
	if err := file.Close(); err != nil {
		return true, err
	}
	if err := managed.ValidateTrustedServiceRuntimeFilePath(path, "device identity file", account); err != nil {
		return true, fmt.Errorf("gateway: validate managed device identity artifact: %w", err)
	}
	return true, nil
}

// standaloneManagedServiceAccount returns the standalone gateway service
// account when this process runs under the standalone managed pins.
func standaloneManagedServiceAccount() (string, bool) {
	if !managed.IsManagedEnterprise(managed.PinnedDeploymentMode()) ||
		!managed.IsStandaloneProfile(os.Getenv(managed.EnterpriseProfileEnv)) {
		return "", false
	}
	account := strings.TrimSpace(os.Getenv(managed.WindowsServiceAccountEnv))
	return account, account != ""
}
