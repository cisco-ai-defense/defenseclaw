// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import "strings"

// RemoveWindowsSecureClientPerUserRuntimeDirectories is the last step of a
// Secure Client managed-hook teardown or first-install rollback. Once the
// enrollment and selector are gone, DefenseClaw's folder in Copilot's machine
// folder (%ProgramData%\GitHub\Copilot\DefenseClaw) holds only lock files; it
// loses them and is removed. A folder that still holds anything else is left
// in place and returned, and Copilot's own folders are never touched.
func RemoveWindowsSecureClientPerUserRuntimeDirectories() ([]string, error) {
	if windowsPerUserRuntimeStandalone() {
		return nil, nil
	}
	var kept []string
	for _, name := range WindowsProfilePerUserConnectorNames() {
		directory, err := windowsPerUserManagedRuntimeDir(name)
		if err != nil {
			return kept, err
		}
		removed, err := removeWindowsHookRuntimeConnectorDirectory(directory)
		if err != nil {
			return kept, err
		}
		if !removed {
			kept = append(kept, directory)
		}
	}
	return kept, nil
}

// windowsSecureClientCopilotVersion is a Secure Client GitHub Copilot row's
// version when no npm package records one: the WinGet GitHub.Copilot package
// (the machine's, then the user's while the user's hive is loaded), then the
// CLI release the GitHub Copilot app runs. Like every other probe it only
// reads; nothing the user owns is executed.
func windowsSecureClientCopilotVersion(profileHome, sid string) string {
	for _, packageID := range windowsWinGetPackageIDs["copilot"] {
		if version, _ := windowsMachineWinGetPackageVersion(packageID); version != "" {
			return version
		}
	}
	if sid = strings.TrimSpace(sid); sid != "" {
		for _, packageID := range windowsWinGetPackageIDs["copilot"] {
			if version, _ := windowsUserWinGetPackageVersion(sid, packageID); version != "" {
				return version
			}
		}
	}
	return discoverWindowsCopilotAppCLIVersion(profileHome)
}
