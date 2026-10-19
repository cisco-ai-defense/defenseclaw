// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"os"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// An uncertain deployment must not cause personal config/.env loading. Presence
// only denies that read; it never establishes managed authority or a profile.
// Resolve the metadata path from protected HKLM roots, not process environment.
var sandboxWindowsPersonalConfigPermitted = func() bool {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, WindowsEnterpriseMarkerKey, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err == nil {
		_ = key.Close()
		return false
	}
	if !sandboxWindowsRegistryPathAbsent(err) {
		return false
	}
	for _, profile := range []string{managed.ProfileStandalone, managed.ProfileSecureClient} {
		roots, err := winpath.TrustedEnterpriseRoots(profile)
		if err != nil {
			return false
		}
		// The existing Secure Client detector treats a present state root as
		// managed. An access error cannot establish its absence either.
		if profile == managed.ProfileSecureClient && !sandboxWindowsStateRootAbsent(roots.StateRoot) {
			return false
		}
		if !sandboxWindowsPersonalConfigPermittedAt(profile, roots.MetadataPath) {
			return false
		}
	}
	return true
}

func sandboxWindowsRegistryPathAbsent(err error) bool {
	return errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND)
}

func sandboxWindowsStateRootAbsent(path string) bool {
	_, err := os.Lstat(path)
	return errors.Is(err, os.ErrNotExist)
}

func sandboxWindowsPersonalConfigPermittedAt(profile, path string) bool {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	if err != nil || !info.Mode().IsRegular() || managedHostRecordTrusted(path) != nil {
		return false
	}
	// Only an administrator-written uninstall tombstone can permit the read
	// when metadata exists. Never interpret an untrusted record's bytes.
	deployment, err := winpath.InspectEnterpriseDeploymentAt(profile, path)
	return err == nil && deployment.State == winpath.EnterpriseDeploymentTombstone
}
