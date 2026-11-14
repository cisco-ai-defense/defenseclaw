// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/hookcli"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// managedHostWindowsStandalone reports a standalone managed deployment. Two
// administrator-written signals count, and nothing a standard user can
// create does (%ProgramData% lets any user create folders, so a planted
// record would otherwise refuse every other user's per-user gateway):
//
//   - the HKLM marker the elevated standalone lifecycle publishes after a
//     successful install and removes after uninstall, honored only when its
//     key is owned by SYSTEM, Administrators or TrustedInstaller and no
//     other principal can write it (managedHostStandaloneMarker);
//   - the ProgramData deployment record, when no one but an administrator
//     could have written it (managedHostRecordTrusted) or the
//     administrator-registered standalone gateway service confirms it
//     (managedStandaloneRecordCounts). An uninstalled deployment (tombstone)
//     does not count.
//
// Secure Client hosts are unaffected: only the standalone profile writes the
// marker, and their record lives under the Secure Client roots, which this
// profile's inspection never reads.
// secureClientHost uses machine roots, a trusted installation, and its
// registered service. An ordinary user may be unable to read the protected
// deployment record; that does not demote an otherwise verified installation.
// A first install writes that record only when its lifecycle transaction
// commits; until then the transaction's own protected record
// (install\pending.json) stands in for it, so the target enumeration and the
// helpers the install runs apply the Secure Client rules, as they already do
// for Repair and Upgrade.
func init() {
	managed.SecureClientHostVerified = func() bool { return hookcli.SecureClientHost() }
	managed.SecureClientProcessPathVerified = secureClientManagedProcessPath
}

// secureClientManagedProcessPath binds the managed trust exceptions to the
// installed gateway service or hook executable and the installation's exact
// state tree. Neither the process home nor its deployment-mode environment
// pin selects these paths.
func secureClientManagedProcessPath(path string) bool {
	roots, err := winpath.TrustedEnterpriseRoots(winpath.EnterpriseProfileSecureClient)
	if err != nil {
		return false
	}
	executable, err := os.Executable()
	if err != nil || !secureClientManagedLayoutMatches(roots, executable, path, managed.WindowsCurrentProcessIsGatewayService()) {
		return false
	}
	return managed.ValidateTrustedSecureClientHostFile(executable, "Secure Client process executable") == nil
}

func secureClientManagedLayoutMatches(roots winpath.EnterpriseRoots, executable, path string, gatewayService bool) bool {
	bin := filepath.Join(roots.InstallRoot, "bin")
	installed := (gatewayService && strings.EqualFold(filepath.Clean(executable), filepath.Join(bin, "defenseclaw-gateway.exe"))) ||
		strings.EqualFold(filepath.Clean(executable), filepath.Join(bin, "defenseclaw-hook.exe"))
	if !installed {
		return false
	}
	state := strings.ToLower(filepath.Clean(roots.StateRoot)) + string(filepath.Separator)
	return strings.HasPrefix(strings.ToLower(filepath.Clean(path)), state)
}
