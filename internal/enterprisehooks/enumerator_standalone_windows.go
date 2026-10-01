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

package enterprisehooks

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// windowsNativeClaudeMaxVersionEntries bounds the native installer's
// versions directory walk; a hostile profile cannot make the LocalSystem
// enumerator iterate an unbounded directory.
const windowsNativeClaudeMaxVersionEntries = 64

// windowsWinGetUninstallKey is the machine-wide ARP root where WinGet records
// machine-scope portable packages as "<PackageIdentifier>_<SourceIdentifier>"
// subkeys with a DisplayVersion. Only administrators can write it.
const windowsWinGetUninstallKey = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`

// windowsWinGetPackageIDs maps a connector to the WinGet package identifiers
// that ship its CLI.
var windowsWinGetPackageIDs = map[string][]string{
	"claudecode": {"Anthropic.ClaudeCode"},
	"codex":      {"OpenAI.Codex"},
}

// windowsMachineWinGetPackageVersion is the registry seam for machine-scope
// WinGet discovery so tests do not depend on HKLM contents.
var windowsMachineWinGetPackageVersion = readWindowsMachineWinGetPackageVersion

// windowsStandaloneRowContext is what the standalone row policy knows about
// the profile beyond its manifest rows.
type windowsStandaloneRowContext struct {
	// sessionActive: the user has an active session now, so the guardian
	// can re-render the user's hooks for a changed agent version at once.
	sessionActive bool
	// user names the profile in reports (its directory name).
	user string
	// report receives agents found installed but not enrollable.
	report func(UnprotectedAgent)
}

// unprotected reports an installed agent that has no row: it is not
// enrolled.
func (c windowsStandaloneRowContext) unprotected(row *ManifestTarget, version, reason string) {
	consequence := "it runs without DefenseClaw hooks"
	if windowsStandaloneMachinePolicyConnector(row.Connector) {
		consequence = "its machine-policy hooks refuse this user's tool calls until it is enrolled"
		if strings.EqualFold(strings.TrimSpace(row.Connector), "cursor") && !windowsCursorMachinePolicyPublished() {
			consequence = windowsCursorUnpublishedConsequence
		}
	}
	c.reportAgent(row, version, reason, consequence)
}

// windowsCursorUnpublishedConsequence is the unprotected-agent consequence for
// Cursor while its machine hooks file is not published.
const windowsCursorUnpublishedConsequence = "no user is enrolled for Cursor, so the guardian has not published Cursor's machine hooks file and it runs without DefenseClaw hooks"

// windowsCursorMachinePolicyPublished reports whether Cursor's machine hooks
// file is in force. The guardian publishes it only while at least one user is
// enrolled for Cursor (an empty target set deactivates it), so with no
// enrolled Cursor user there is no machine hook to refuse anyone. A policy
// that cannot be read or validated counts as published: its adapter refuses
// unregistered users. Replaced in tests.
var windowsCursorMachinePolicyPublished = func() bool {
	_, active, err := ReadWindowsCursorManagedPolicyTargets()
	return err != nil || active
}

// keptAt reports an installed version a known row does not follow: the row
// stays enrolled at kept, so the user's hooks stay those rendered for it.
func (c windowsStandaloneRowContext) keptAt(row *ManifestTarget, installed, reason, kept string) {
	c.reportAgent(row, installed, reason, fmt.Sprintf("the row stays enrolled at %s, so this user's hooks stay rendered for %s, not for the installed version", kept, kept))
}

// pending reports an agent installed for a signed-in user whose enrollment
// is undecided this cycle: they can run it now, and it gets no row until
// the decision is made. A signed-out user's pending agent is not reported,
// since it cannot run until the user signs in and the next cycle decides.
func (c windowsStandaloneRowContext) pending(row *ManifestTarget, reason string) {
	if c.report == nil || !c.sessionActive {
		return
	}
	version, _ := standaloneWindowsAgentVersionExplain(row.UserHome, row.Connector)
	if version == "" {
		if path, _ := windowsStandalonePerUserManagedExecutable(row.UserHome, row.Connector); path == "" {
			return
		}
	}
	c.unprotected(row, version, "its enrollment is pending: "+reason)
}

func (c windowsStandaloneRowContext) reportAgent(row *ManifestTarget, version, reason, consequence string) {
	if c.report == nil {
		return
	}
	c.report(UnprotectedAgent{
		User:      c.user,
		SID:       canonicalManifestTargetSID(row.SID),
		Connector: strings.ToLower(strings.TrimSpace(row.Connector)),
		Version:   version,
		Code:      UnprotectedCodeForReason(reason),
		Reason:    reason + "; " + consequence,
	})
}

// applyStandaloneRowState is the standalone profile's row policy for a
// profile with no active session; see applyStandaloneRowStateFor.
func applyStandaloneRowState(row *ManifestTarget, previous map[string]ManifestTarget, logf EnumerationLogger) bool {
	return applyStandaloneRowStateFor(row, previous, logf, windowsStandaloneRowContext{})
}

// applyStandaloneRowStateFor is the standalone profile's row policy. A row
// that already exists in the manifest keeps its state as in
// applyPreviousRowState, except its agent version: while the user has an
// active session the version is discovered again, and a change is taken
// when the new version is admitted (a known, verified hook contract at or
// above the platform minimum), so the guardian re-renders and re-verifies
// the user's hooks for it. A change to a version that is not admitted keeps
// the row at its last verified version and is reported as unprotected
// (hook_contract_unverified for an unverified version). So does a Claude
// Code change to an older hook contract: the one machine-wide Claude policy
// is rendered from the oldest enrolled contract, so following it would let
// one user weaken the policy every user shares. A signed-out user's
// version is left alone: the guardian could not repair their hooks until
// they sign in, and the failure would withhold enrollment publication for
// every other user.
//
// A newly discovered (SID, Connector) row is emitted only when standalone
// discovery finds the connector's CLI, and then as an enabled, deferred row
// at the discovered version: the ProfileList walk also finds signed-out and
// disconnected users, and a deferred row lets the guardian report such a
// user as pending instead of counting a reconcile failure that would
// withhold enrollment publication for every other user. A deferred row
// whose user is signed in installs immediately. A CLI found at a version
// that is not admitted is reported as unprotected instead of written.
func applyStandaloneRowStateFor(row *ManifestTarget, previous map[string]ManifestTarget, logf EnumerationLogger, rowContext windowsStandaloneRowContext) bool {
	if row == nil {
		return false
	}
	if prev, known := previous[previousManifestKey(row.SID, row.Connector)]; known {
		// A disabled row is an administrator decision the guardian never
		// installs; keep it so rediscovery cannot re-enable it.
		if !prev.IsEnabled() {
			return applyPreviousRowState(row, previous, logf)
		}
		version := prev.AgentVersion
		// notFollowed is an installed version the row does not take, and
		// why; it is reported once the row's own fate is known.
		var notFollowed, notFollowedReason string
		if rowContext.sessionActive {
			discovered, _ := standaloneWindowsAgentVersionExplain(row.UserHome, row.Connector)
			if discovered != "" && discovered != prev.AgentVersion {
				ok, reason := windowsStandaloneRowAdmission(row.UserHome, row.Connector, discovered)
				if ok {
					if lowered := claudeMachineContractLowered(row.Connector, prev.AgentVersion, discovered); lowered != "" {
						ok, reason = false, lowered
					}
				}
				if ok {
					logfSafely(logf, row.SID, fmt.Sprintf("(SID, %s) agent version changed from %s to %s, which has a known hook contract; the guardian re-renders and re-verifies its hooks", row.Connector, prev.AgentVersion, discovered))
					version = discovered
				} else {
					logfSafely(logf, row.SID, fmt.Sprintf("(SID, %s) agent version changed from %s to %s, which is not followed (%s); keeping the row at its last verified version", row.Connector, prev.AgentVersion, discovered, reason))
					notFollowed, notFollowedReason = discovered, reason
				}
			}
		}
		if ok, reason := windowsStandaloneRowAdmission(row.UserHome, row.Connector, version); !ok {
			logfSafely(logf, row.SID, fmt.Sprintf("(SID, %s) row dropped: %s", row.Connector, reason))
			switch {
			case notFollowed != "":
				rowContext.unprotected(row, notFollowed, notFollowedReason)
			default:
				// Report it only while the agent is still installed: a row
				// dropped because the user removed the agent is no gap.
				if current, _ := standaloneWindowsAgentVersionExplain(row.UserHome, row.Connector); current != "" {
					rowContext.unprotected(row, version, reason)
				}
			}
			return false
		}
		if notFollowed != "" {
			rowContext.keptAt(row, notFollowed, notFollowedReason, version)
		}
		emit := applyPreviousRowState(row, previous, logf)
		row.AgentVersion = version
		if emit {
			reportWindowsRefusedSurfaces(row, logf, rowContext)
		}
		return emit
	}
	version, reason := standaloneWindowsAgentVersionExplain(row.UserHome, row.Connector)
	cliVersion := version
	if version == "" {
		// A user with only the desktop app or an editor extension is
		// enrolled at its admitted engine version.
		version = windowsStandaloneSurfaceVersion(row, logf, rowContext)
	}
	if version == "" {
		logfSafely(logf, row.SID, fmt.Sprintf("newly-discovered (SID, %s) row skipped: %s", row.Connector, reason))
		path, _ := windowsStandalonePerUserManagedExecutable(row.UserHome, row.Connector)
		if path == "" {
			// A desktop app that runs the agent (Devin Desktop) is an
			// install too.
			path = windowsDesktopSurfaceInstalled(row.UserHome, row.Connector)
		}
		if path != "" {
			rowContext.unprotected(row, "", fmt.Sprintf("%s is installed, but its version could not be read, so no hook contract can be selected", path))
		}
		return false
	}
	// A client below the lowest hook contract cannot be protected; writing
	// its row would only produce a guardian failure for this user.
	if minimum := windowsEnterpriseStandaloneAgentMinimum(row.Connector); minimum != "" {
		normalized := connector.NormalizeAgentVersion(row.Connector, version)
		if normalized == "" || compareWindowsEnterpriseVersion(normalized, minimum) < 0 {
			belowMinimum := fmt.Sprintf("version %s is below the lowest hook contract %s", version, minimum)
			logfSafely(logf, row.SID, fmt.Sprintf("newly-discovered (SID, %s) row skipped: %s", row.Connector, belowMinimum))
			rowContext.unprotected(row, version, belowMinimum)
			return false
		}
	}
	if ok, reason := windowsStandaloneRowAdmission(row.UserHome, row.Connector, version); !ok {
		logfSafely(logf, row.SID, fmt.Sprintf("newly-discovered (SID, %s) row skipped: %s", row.Connector, reason))
		rowContext.unprotected(row, version, reason)
		return false
	}
	enabled := true
	row.AgentVersion = version
	row.Enabled = &enabled
	row.Deferred = true
	if cliVersion != "" {
		reportWindowsRefusedSurfaces(row, logf, rowContext)
	}
	logfSafely(
		logf,
		row.SID,
		fmt.Sprintf(
			"newly-discovered (SID, %s) row auto-authorized (deferred until an active session) at version %s",
			row.Connector,
			version,
		),
	)
	return true
}

// standaloneWindowsAgentVersionExplain is the standalone profile's single
// agent discovery: the per-user package-manager probes shared with the
// Secure Client profile, then the Node version managers (nvm-windows, fnm,
// Volta, pnpm and the .npmrc prefix), then the native per-user installers,
// the native Claude installer (%USERPROFILE%\.local\bin\claude.exe) and the
// native Cursor Agent CLI (%LOCALAPPDATA%\cursor-agent\versions), then
// machine-scope WinGet packages. Cursor Desktop's package.json comes first,
// so a user with both Cursor Desktop and the Agent CLI is enrolled at the
// Desktop version, as before. Every source is static filesystem or registry
// inspection; no discovered binary is executed.
func standaloneWindowsAgentVersionExplain(profileHome, connectorName string) (string, string) {
	connectorName = strings.ToLower(strings.TrimSpace(connectorName))
	version, reason := windowsAgentVersionExplain(profileHome, connectorName)
	if version != "" {
		return version, ""
	}
	reasons := []string{reason}
	if filepath.IsAbs(strings.TrimSpace(profileHome)) {
		if managed := discoverWindowsStandaloneVersionManagerAgentVersion(filepath.Clean(strings.TrimSpace(profileHome)), connectorName); managed != "" {
			return managed, ""
		}
		if native := discoverWindowsStandalonePerUserAgentVersion(
			filepath.Clean(strings.TrimSpace(profileHome)),
			connectorName,
		); native != "" {
			return native, ""
		}
	}
	if connectorName == "claudecode" && filepath.IsAbs(strings.TrimSpace(profileHome)) {
		native, nativeReason := discoverWindowsNativeClaudeVersion(filepath.Clean(strings.TrimSpace(profileHome)))
		if native != "" {
			return native, ""
		}
		reasons = append(reasons, nativeReason)
	}
	if connectorName == "cursor" && filepath.IsAbs(strings.TrimSpace(profileHome)) {
		cli, cliReason := discoverWindowsCursorAgentCLIVersion(filepath.Clean(strings.TrimSpace(profileHome)))
		if cli != "" {
			return cli, ""
		}
		reasons = append(reasons, cliReason)
	}
	for _, packageID := range windowsWinGetPackageIDs[connectorName] {
		machine, machineReason := windowsMachineWinGetPackageVersion(packageID)
		if machine != "" {
			return machine, ""
		}
		reasons = append(reasons, machineReason)
	}
	return "", strings.Join(nonEmptyStrings(reasons), "; ")
}

// discoverWindowsNativeClaudeVersion reads the version of a Claude Code
// native install. The installer copies the active build to
// .local\bin\claude.exe and keeps each build as
// .local\share\claude\versions\<version>; the active version is the entry
// whose size matches the launcher (the highest such version when several
// match). The profile owner controls these files, so the result is only a
// version claim, bounded and validated exactly like a package.json probe.
func discoverWindowsNativeClaudeVersion(profileHome string) (string, string) {
	binDir := filepath.Join(profileHome, ".local", "bin")
	versionsDir := filepath.Join(profileHome, ".local", "share", "claude", "versions")
	launcher := filepath.Join(binDir, "claude.exe")
	for _, directory := range []string{binDir, versionsDir} {
		if err := winpath.RejectReparseChain(directory); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return "", "no native Claude install under this profile"
			}
			return "", "native Claude install has a refused reparse chain"
		}
	}
	launcherInfo, err := os.Lstat(launcher)
	if err != nil {
		return "", "no native Claude launcher under this profile"
	}
	if !launcherInfo.Mode().IsRegular() {
		return "", "native Claude launcher is not a regular file"
	}
	entries, err := os.ReadDir(versionsDir)
	if err != nil {
		return "", "native Claude versions directory is unreadable"
	}
	if len(entries) > windowsNativeClaudeMaxVersionEntries {
		return "", "native Claude versions directory exceeds the bounded entry count"
	}
	best := ""
	for _, entry := range entries {
		name := entry.Name()
		if !isValidWindowsAgentVersion(name) || !windowsNativeClaudeVersionName(name) {
			continue
		}
		info, err := os.Lstat(filepath.Join(versionsDir, name))
		if err != nil || !info.Mode().IsRegular() || info.Size() != launcherInfo.Size() {
			continue
		}
		if best == "" || compareWindowsEnterpriseVersion(name, best) > 0 {
			best = name
		}
	}
	if best == "" {
		return "", "native Claude launcher matches no recorded version"
	}
	return best, ""
}

// windowsNativeClaudeVersionName accepts dotted numeric release names
// (e.g. 2.1.283), the only shape the native installer writes.
func windowsNativeClaudeVersionName(name string) bool {
	parts := strings.Split(name, ".")
	if len(parts) < 2 || len(parts) > 4 {
		return false
	}
	for _, part := range parts {
		if part == "" || len(part) > 9 {
			return false
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

// readWindowsMachineWinGetPackageVersion returns the DisplayVersion of a
// machine-scope WinGet package. WinGet names the ARP subkey
// "<PackageIdentifier>_<SourceIdentifier>"; the machine-wide 64-bit view is
// administrator-only, so the value is an administrator's install record,
// shared by every user on the device.
func readWindowsMachineWinGetPackageVersion(packageID string) (string, string) {
	root, err := registry.OpenKey(registry.LOCAL_MACHINE, windowsWinGetUninstallKey, registry.ENUMERATE_SUB_KEYS|registry.WOW64_64KEY)
	if err != nil {
		return "", "machine uninstall registry is unavailable"
	}
	defer root.Close()
	names, err := root.ReadSubKeyNames(-1)
	if err != nil {
		return "", "machine uninstall registry is unreadable"
	}
	prefix := strings.ToLower(packageID) + "_"
	best := ""
	for _, name := range names {
		if !strings.HasPrefix(strings.ToLower(name), prefix) {
			continue
		}
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, windowsWinGetUninstallKey+`\`+name, registry.QUERY_VALUE|registry.WOW64_64KEY)
		if err != nil {
			continue
		}
		version, _, err := key.GetStringValue("DisplayVersion")
		_ = key.Close()
		version = strings.TrimSpace(version)
		if err != nil || !isValidWindowsAgentVersion(version) {
			continue
		}
		if best == "" || compareWindowsEnterpriseVersion(version, best) > 0 {
			best = version
		}
	}
	if best == "" {
		return "", fmt.Sprintf("no machine-scope WinGet package %s", packageID)
	}
	return best, ""
}

func nonEmptyStrings(values []string) []string {
	out := values[:0]
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, value)
		}
	}
	return out
}
