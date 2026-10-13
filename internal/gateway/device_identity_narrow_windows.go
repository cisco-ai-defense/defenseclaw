// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"golang.org/x/sys/windows"
)

// narrowDeviceIdentityACL gives an existing per-user device identity the DACL
// a new one gets: the current user and LocalSystem only, protected. The
// identity that quickstart and init created up to now also granted
// BUILTIN\Administrators full control, so doctor failed Private files on
// every new install and kept failing after an upgrade (GAP-0911). Only a
// file this account owns and no account other than it, LocalSystem and
// Administrators can write is narrowed; the content and the provenance are
// never touched. A managed service keeps its runtime DACL (Administrators
// snapshot and restore that tree), and failures leave the file as it was.
func narrowDeviceIdentityACL(keyFile, dataDir string) {
	if managed.IsManagedEnterprise(managed.PinnedDeploymentMode()) || !deviceIdentityOwnerIsAccount() {
		return
	}
	for _, path := range []string{keyFile, keyFile + ".provenance", filepath.Join(dataDir, deviceProvenanceSecretName)} {
		if safefile.ValidatePrivateFile(path) == nil {
			continue
		}
		if safefile.ValidatePrivateFileOwnershipAllowingAdministrators(path) != nil {
			continue
		}
		_ = safefile.ProtectFile(path)
	}
}

// deviceIdentityOwnerIsAccount reports a process running as a local or
// domain account (S-1-5-21-...), not LocalSystem or a service SID.
func deviceIdentityOwnerIsAccount() bool {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return false
	}
	return strings.HasPrefix(user.User.Sid.String(), "S-1-5-21-")
}
