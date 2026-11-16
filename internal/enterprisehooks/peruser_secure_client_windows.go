// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"os"
	"path/filepath"
	"strings"
)

// RemoveWindowsSecureClientPerUserRuntimeDirectories is the last step of a
// Secure Client managed-hook teardown or first-install rollback. Once the
// enrollment and selector are gone, DefenseClaw's folder in Copilot's machine
// folder (%ProgramData%\GitHub\Copilot\DefenseClaw) holds only lock files; it
// loses them and is removed, and so are the Copilot and GitHub folders above
// it when nothing else is left in them. A folder that still holds anything
// else is left in place; DefenseClaw's own is returned.
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
		existed, err := windowsHookRuntimePlainDirectory(directory)
		if err != nil {
			return kept, err
		}
		removed, err := removeWindowsHookRuntimeConnectorDirectory(directory)
		if err != nil {
			return kept, err
		}
		if !removed {
			kept = append(kept, directory)
			continue
		}
		if existed {
			removeEmptyWindowsCopilotFolders(directory)
		}
	}
	return kept, nil
}

// removeEmptyWindowsCopilotFolders removes the Copilot folder and the GitHub
// folder above DefenseClaw's once they are empty plain directories: the
// policy publication created them for DefenseClaw's drop-in, and the drop-in
// and DefenseClaw's folder are gone. Any other content keeps them.
func removeEmptyWindowsCopilotFolders(directory string) {
	for _, folder := range []string{filepath.Dir(directory), filepath.Dir(filepath.Dir(directory))} {
		if exists, err := windowsHookRuntimePlainDirectory(folder); err != nil || !exists {
			return
		}
		if err := os.Remove(folder); err != nil {
			return
		}
	}
}

// windowsSecureClientAgentVersionExplain is a Secure Client row's version
// from the sources the installer reads: the npm, bun and yarn packages, then,
// for Claude Code and Codex, the machine's and the user's WinGet package (the
// user's while the user's hive is loaded). The enumerator refreshes a known
// row's version from it on every pass, so a source the installer reads but
// this probe does not would erase the installer's version. Like every other
// probe it only reads; nothing the user owns is executed.
func windowsSecureClientAgentVersionExplain(profileHome, sid, connectorName string) (string, string) {
	version, reason := windowsAgentVersionExplain(profileHome, connectorName)
	connectorName = strings.ToLower(strings.TrimSpace(connectorName))
	if version != "" || (connectorName != "claudecode" && connectorName != "codex") {
		return version, reason
	}
	reasons := []string{reason}
	for _, packageID := range windowsWinGetPackageIDs[connectorName] {
		machine, machineReason := windowsMachineWinGetPackageVersion(packageID)
		if machine != "" {
			return machine, ""
		}
		reasons = append(reasons, machineReason)
	}
	if sid = strings.TrimSpace(sid); sid != "" {
		for _, packageID := range windowsWinGetPackageIDs[connectorName] {
			user, userReason := windowsUserWinGetPackageVersion(sid, packageID)
			if user != "" {
				return user, ""
			}
			reasons = append(reasons, userReason)
		}
	}
	return "", strings.Join(nonEmptyStrings(reasons), "; ")
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
