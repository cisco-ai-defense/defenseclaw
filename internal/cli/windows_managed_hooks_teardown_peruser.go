// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// Windows SYSTEM can open an enrolled user's profile even when that user has
// no logon token. An elevated owner can clean its own profile too. The profile
// root is checked against the recorded SID; the connector transaction then
// pins the settings identity, converges unsafe protection for a foreign
// enrolled owner, and preserves that owner and the converged DACL.
//
// It also returns, from the same transaction, each hook command the settings
// it committed (or found unchanged) still hold that names a DefenseClaw
// launcher, described without its arguments (#1286). A file it cannot
// inspect fails the cleanup instead of reporting none.
func removeWindowsManagedClaudeUserSettings(home, sid, _ string) (int, []string, error) {
	if _, err := enterprisehooks.ValidateWindowsEnterpriseHome(home, sid); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil, nil
		}
		return 0, nil, err
	}
	path := filepath.Join(home, ".claude", "settings.json")
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return 0, nil, nil
	} else if err != nil {
		return 0, nil, err
	}
	launcher := filepath.Join(home, ".local", "bin", "defenseclaw-hook.exe")
	// The managed runtime is owned by Builtin Administrators, including after
	// Setup runs as SYSTEM. safefile requires its transaction directory to be
	// owned by the current token, so keep these receipts in that token's
	// private cache. The path is stable across retries and independent of the
	// runtime directory, which uninstall may already have retired.
	transactionDir, err := windowsManagedClaudeTransactionDir()
	if err != nil {
		return 0, nil, err
	}
	var left []string
	removed, err := connector.TransformWindowsClaudeSettingsForUninstall(path, transactionDir, sid, func(raw []byte) ([]byte, int, error) {
		left = nil
		out, count, err := removeWindowsManagedClaudeCommands(raw, launcher)
		if err != nil {
			return nil, 0, err
		}
		if left, err = windowsClaudeHooksNamingDefenseClaw(out); err != nil {
			return nil, 0, err
		}
		return out, count, nil
	})
	if err != nil {
		return 0, nil, err
	}
	return removed, left, nil
}

func windowsManagedClaudeTransactionDir() (string, error) {
	cache, err := winpath.CurrentUserKnownFolderPath(windows.FOLDERID_LocalAppData)
	if err != nil {
		return "", fmt.Errorf("resolve current-token Claude cleanup transaction directory: %w", err)
	}
	return filepath.Join(cache, "DefenseClaw", "claude-settings-teardown"), nil
}

var windowsManagedClaudeSettingsRemover = removeWindowsManagedClaudeUserSettings

// The current Claude enrollment uses machine policy. An older per-user hook
// warrants a pending warning only when its exact launcher is still present.
// When none is, it also returns, read-only, each hook command that still
// names a DefenseClaw launcher (an edited guard, another form of the profile
// path, defenseclaw-gateway), so a file holding only hooks the remover keeps
// is reported rather than passed over.
func windowsManagedClaudeRegistrationPresent(home, sid string) (bool, []string, error) {
	raw, err := windowsManagedClaudeUserSettingsReader(home, sid)
	if err != nil || raw == nil {
		return false, nil, err
	}
	launcher := filepath.Join(home, ".local", "bin", "defenseclaw-hook.exe")
	_, count, err := removeWindowsManagedClaudeCommands(raw, launcher)
	if err != nil || count > 0 {
		return count > 0, nil, err
	}
	left, err := windowsClaudeHooksNamingDefenseClaw(raw)
	return false, left, err
}

var windowsManagedClaudeRegistrationProbe = windowsManagedClaudeRegistrationPresent

// readWindowsManagedClaudeUserSettings reads the account's Claude Code user
// settings after checking the profile against the recorded SID; nil, with no
// error, when the profile or the file is absent.
func readWindowsManagedClaudeUserSettings(home, sid string) ([]byte, error) {
	if _, err := enterprisehooks.ValidateWindowsEnterpriseHome(home, sid); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	// Match the connector's 32 MiB atomic settings limit.
	raw, err := safefile.ReadRegularFileBounded(filepath.Join(home, ".claude", "settings.json"), 32<<20)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return raw, err
}

var windowsManagedClaudeUserSettingsReader = readWindowsManagedClaudeUserSettings

// An elevated Setup can edit its own Claude settings without impersonating
// another account. All other user profiles still require LocalSystem.
var windowsManagedClaudeCurrentUserSID = func() (string, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	if user == nil || user.User.Sid == nil {
		return "", errors.New("current Windows user SID is unavailable")
	}
	return user.User.Sid.String(), nil
}

// Standalone per-user connectors (Copilot, Antigravity, Devin, Hermes,
// OpenCode, Amp) are part of the managed-hook teardown in a process pinned to
// the standalone profile, and Copilot alone in a Secure Client process. Their
// machine wiring is the per-user enrollment and runtime selector of each
// hook-binary connector, plus the Go-owned Copilot machine policy (and, on
// the standalone profile, the public summary). After the uninstall commits,
// a standalone finalize also removes DefenseClaw's own registration or
// plugin from each user's agent configuration, as that user (see
// removeWindowsManagedHooksStandalonePerUserRegistrations); Secure Client
// writes none. Per-user runtime files stay, like every other connector.

func windowsManagedHooksStandalonePerUserTarget(connectorName string) bool {
	return enterprisehooks.IsWindowsProfilePerUserConnector(connectorName)
}

// windowsManagedHooksStandalonePerUserExpected is the enrollment an
// activated deployment carries: every activated, non-pending target of each
// hook-binary per-user connector.
func windowsManagedHooksStandalonePerUserExpected(
	identity windowsManagedHooksTeardownJournal,
) map[string][]enterprisehooks.WindowsPerUserManagedEnrollmentTarget {
	expected := map[string][]enterprisehooks.WindowsPerUserManagedEnrollmentTarget{}
	for _, target := range identity.Targets {
		hookBinary, perUser := enterprisehooks.IsWindowsStandalonePerUserConnector(target.Connector)
		if !perUser || !hookBinary {
			continue
		}
		expected[target.Connector] = expected[target.Connector]
		if !windowsManagedHooksTeardownSelectorExpected(target, identity.PendingTargets, identity.ActivationState) {
			continue
		}
		expected[target.Connector] = append(expected[target.Connector],
			enterprisehooks.WindowsPerUserManagedEnrollmentTarget{SID: target.SID, DataDir: target.DataDir})
	}
	return expected
}

func validateWindowsManagedHooksStandalonePerUserEnrollment(identity windowsManagedHooksTeardownJournal) error {
	for connectorName, want := range windowsManagedHooksStandalonePerUserExpected(identity) {
		current, exists, err := enterprisehooks.ReadWindowsPerUserManagedEnrollmentTargets(connectorName)
		if err != nil {
			return err
		}
		if exists != (len(want) != 0) || !equalWindowsPerUserEnrollmentTargets(current, want) {
			return fmt.Errorf("%s machine enrollment does not match the authenticated activation state", connectorName)
		}
	}
	return nil
}

func equalWindowsPerUserEnrollmentTargets(left, right []enterprisehooks.WindowsPerUserManagedEnrollmentTarget) bool {
	if len(left) != len(right) {
		return false
	}
	index := map[string]string{}
	for _, target := range left {
		index[strings.ToUpper(target.SID)] = target.DataDir
	}
	for _, target := range right {
		dataDir, ok := index[strings.ToUpper(target.SID)]
		if !ok || !sameWindowsEnterprisePathCLI(dataDir, target.DataDir) {
			return false
		}
	}
	return true
}

func removeWindowsManagedHooksStandalonePerUserWiring(identity windowsManagedHooksTeardownJournal) error {
	if !enterprisehooks.WindowsStandaloneProcess() {
		return removeWindowsSecureClientCopilotWiring(identity.HookBinary)
	}
	// Revoke every per-user enrollment, not only the manifest connectors, so
	// an uninstall leaves no enrolled SID behind.
	if err := enterprisehooks.RemoveWindowsPerUserManagedEnrollments(
		identity.HookBinary,
		enterprisehooks.WindowsStandalonePerUserConnectorNames(),
	); err != nil {
		return err
	}
	layout, programFiles, programData, err := standaloneEnterprisePolicyLayout()
	if err != nil {
		return err
	}
	opts := enterprisepolicy.LayoutOptions(layout, programFiles, programData)
	if _, err := enterprisepolicy.RemoveWindowsGoOwned(opts); err != nil {
		return err
	}
	// The Claude Code version floor drop-in goes with the rest of the
	// standalone machine policy. A rollback does not put it back: the
	// guardian's next reconcile does, once the rolled-back services start.
	if _, err := enterprisepolicy.RemoveWindowsClaudeVersionFloor(opts); err != nil {
		return err
	}
	// So do the WSL registry values DefenseClaw wrote.
	_, err = enterprisepolicy.RemoveWindowsWSL(opts)
	return err
}

// windowsManagedHooksStandaloneFloorPurger is replaceable in tests.
var windowsManagedHooksStandaloneFloorPurger = purgeWindowsManagedHooksUnrecordedClaudeFloor

// purgeWindowsManagedHooksUnrecordedClaudeFloor is the purge step for a
// Claude Code version floor drop-in that holds DefenseClaw's floor but whose
// ownership record is gone (a rolled-back install left it), which the
// teardown's recorded removal keeps.
func purgeWindowsManagedHooksUnrecordedClaudeFloor() error {
	layout, programFiles, programData, err := standaloneEnterprisePolicyLayout()
	if err != nil {
		return err
	}
	if _, err := enterprisepolicy.PurgeWindowsUnrecordedClaudeVersionFloor(
		enterprisepolicy.LayoutOptions(layout, programFiles, programData),
	); err != nil {
		return err
	}
	removeEmptyWindowsClaudeManagedSettingsFolders(programFiles)
	return nil
}

// removeEmptyWindowsClaudeManagedSettingsFolders removes Claude Code's
// managed-settings.d, and then its ClaudeCode folder, under programFiles when
// the purge left them empty. Setup creates them for its drop-ins. A folder
// that holds anything, or is not a plain directory, stays.
func removeEmptyWindowsClaudeManagedSettingsFolders(programFiles string) {
	root := filepath.Join(programFiles, "ClaudeCode")
	for _, dir := range []string{filepath.Join(root, "managed-settings.d"), root} {
		info, err := os.Lstat(dir)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeType != os.ModeDir {
			return
		}
		if err := os.Remove(dir); err != nil {
			return
		}
	}
}

func restoreWindowsManagedHooksStandalonePerUserEnrollments(journal windowsManagedHooksTeardownJournal) error {
	var errs []error
	for connectorName, targets := range windowsManagedHooksStandalonePerUserExpected(journal) {
		if len(targets) == 0 {
			continue
		}
		if err := enterprisehooks.RestoreWindowsPerUserManagedEnrollment(connectorName, journal.HookBinary, targets); err != nil {
			errs = append(errs, err)
		}
	}
	// The Go-owned Copilot policy and summary are republished by the
	// guardian's next reconcile once the rolled-back services start.
	return errors.Join(errs...)
}

func verifyWindowsManagedHooksStandalonePerUserClean() error {
	for _, connectorName := range enterprisehooks.WindowsProfilePerUserConnectorNames() {
		_, exists, err := enterprisehooks.ReadWindowsPerUserManagedEnrollmentTargets(connectorName)
		if err != nil {
			return err
		}
		if exists {
			return fmt.Errorf("%s machine enrollment survived managed-hook teardown", connectorName)
		}
	}
	if !enterprisehooks.WindowsStandaloneProcess() {
		return nil
	}
	layout, programFiles, programData, err := standaloneEnterprisePolicyLayout()
	if err != nil {
		return err
	}
	recorded, err := enterprisepolicy.ClaudeVersionFloorRecorded(enterprisepolicy.LayoutOptions(layout, programFiles, programData))
	if err != nil {
		return err
	}
	if recorded {
		return errors.New("the Claude Code version floor drop-in survived managed-hook teardown")
	}
	return nil
}

// windowsManagedHooksStandaloneUserCleanups lists the per-user registrations
// an uninstall removes: the guardian's protected per-user rows, the
// cleanups it recorded for signed-out users, and enabled manifest rows that
// were not deferred. A deferred row the guardian never protected has
// nothing to remove unless an earlier install enrolled that user, which
// left the user's DefenseClaw data folder, and DefenseClaw's registration
// is still in the user's agent configuration: then it is attempted and,
// without an active session, reported as pending instead of silently kept
// (GAP-1795, GAP-2023).
func windowsManagedHooksStandaloneUserCleanups(
	runtimeDir string,
	manifest enterprisehooks.Manifest,
	now time.Time,
) ([]enterpriseHookUserCleanup, []string) {
	var problems []string
	var rows []enterpriseHookReconcileRow
	if authorization, _, err := loadEnterpriseHookGuardianAuthorization(runtimeDir); err != nil {
		problems = append(problems, "guardian records: "+boundedEnterpriseHookUserCleanupText(err.Error()))
	} else {
		rows = append(rows, authorization.ProtectedTargets...)
	}
	for _, target := range manifest.Targets {
		if !target.IsEnabled() || (target.IsDeferred() && !windowsManagedHooksStandaloneRegistrationMayRemain(target)) {
			continue
		}
		rows = append(rows, enterpriseHookReconcileRow{
			User:      target.User,
			UserHome:  target.UserHome,
			SID:       target.SID,
			Connector: target.Connector,
			Result:    &enterprisehooks.InstallResult{DataDir: target.DataDir},
		})
	}
	pending, err := loadEnterpriseHookUserCleanups(runtimeDir)
	if err != nil {
		problems = append(problems, "pending cleanups: "+boundedEnterpriseHookUserCleanupText(err.Error()))
	}
	// Every entry is attempted now, whatever its retry state.
	for index := range pending {
		pending[index].Attempts = 0
		pending[index].LastAttemptAt = ""
		pending[index].LastError = ""
	}
	nobody := func(string, string) bool { return false }
	return planEnterpriseHookUserCleanups(pending, rows, nobody, windowsStandalonePerUserCleanupConnector, now), problems
}

// windowsManagedHooksStandaloneRegistrationMayRemain reports whether a
// deferred row may still hold an earlier install's registration: the user's
// DefenseClaw data folder is there and a read of the user's agent
// configuration finds DefenseClaw's registration, or cannot tell. A user
// whose registrations an earlier uninstall already removed has nothing to
// report (GAP-2023).
func windowsManagedHooksStandaloneRegistrationMayRemain(target enterprisehooks.ManifestTarget) bool {
	if !windowsManagedHooksStandaloneEnrolledBefore(target) {
		return false
	}
	return !windowsManagedHooksStandaloneRegistrationGone(target)
}

// windowsManagedHooksStandaloneRegistrationGone reports whether a read of the
// user's agent configuration finds no DefenseClaw registration for the
// target. A read that cannot tell keeps the row.
func windowsManagedHooksStandaloneRegistrationGone(target enterprisehooks.ManifestTarget) bool {
	present, err := windowsManagedHooksStandaloneRegistrationPresent(target)
	return err == nil && !present
}

// windowsManagedHooksStandaloneRegistrationPresent is replaceable in tests.
var windowsManagedHooksStandaloneRegistrationPresent = func(target enterprisehooks.ManifestTarget) (bool, error) {
	name := strings.ToLower(strings.TrimSpace(target.Connector))
	present, err := enterprisehooks.WindowsStandalonePerUserRegistrationPresent(enterprisehooks.InstallOptions{
		ConnectorName: name,
		UserHome:      strings.TrimSpace(target.UserHome),
		OwnerSID:      strings.TrimSpace(target.SID),
		DataDir:       strings.TrimSpace(target.DataDir),
		Registry:      enterpriseHooksCertifiedRegistryFactory(),
	})
	if err != nil || present || name != "copilot" {
		return present, err
	}
	// Copilot's registration is also the VS Code Local hook file and plugin,
	// whose encoded bridge the hook-command search cannot read (GAP-2098).
	return windowsCopilotVSCodeUserFilesLeft(strings.TrimSpace(target.UserHome))
}

// windowsManagedHooksStandaloneEnrolledBefore reports whether the target's
// DefenseClaw data folder exists, which an enrollment creates and a default
// uninstall keeps.
func windowsManagedHooksStandaloneEnrolledBefore(target enterprisehooks.ManifestTarget) bool {
	dataDir := strings.TrimSpace(target.DataDir)
	if dataDir == "" && strings.TrimSpace(target.UserHome) != "" {
		dataDir = filepath.Join(strings.TrimSpace(target.UserHome), ".defenseclaw")
	}
	if dataDir == "" {
		return false
	}
	info, err := os.Lstat(dataDir)
	return err == nil && info.IsDir()
}

// windowsManagedHooksRegistrationsNotRemovedPrefix starts the failure an
// uninstall that is not LocalSystem records for every user registration.
const windowsManagedHooksRegistrationsNotRemovedPrefix = "per-user registrations were not removed: "

// removeWindowsManagedHooksStandalonePerUserRegistrations runs, after a
// committed uninstall, each per-user connector's teardown as the user for
// every registration DefenseClaw made. It is best effort: the uninstall has
// already revoked every enrollment, so a leftover registration can no longer
// reach a gateway. Registrations that require another user's token when the
// uninstall does not run as LocalSystem are reported as pending; there is no
// guardian left to clean them at their next sign-in.
func removeWindowsManagedHooksStandalonePerUserRegistrations(
	ctx context.Context,
	runtimeDir string,
	manifest enterprisehooks.Manifest,
) enterpriseHookUserCleanupResult {
	now := time.Now()
	entries, problems := windowsManagedHooksStandaloneUserCleanups(runtimeDir, manifest, now)
	result := enterpriseHookUserCleanupResult{Failed: problems}
	// Claude's current enrollment is machine policy, but older native hook
	// registrations can remain in user settings. Remove only this profile's
	// exact launcher path before a purge deletes the launcher.
	identityErr := enterpriseHookWindowsUserCleanupIdentity()
	seen := map[string]bool{}
	blockedClaude := false
	for _, target := range manifest.Targets {
		if target.Connector != "claudecode" || target.UserHome == "" || target.SID == "" || seen[target.SID] {
			continue
		}
		seen[target.SID] = true
		if identityErr != nil {
			callerSID, callerErr := windowsManagedClaudeCurrentUserSID()
			if callerErr != nil || !strings.EqualFold(callerSID, target.SID) {
				present, left, err := windowsManagedClaudeRegistrationProbe(target.UserHome, target.SID)
				if err != nil {
					result.Failed = append(result.Failed, "claudecode/"+target.SID+": "+boundedEnterpriseHookUserCleanupText(err.Error()))
				} else if present {
					result.Pending = append(result.Pending, "claudecode/"+target.SID)
					blockedClaude = true
				}
				settings := filepath.Join(target.UserHome, ".claude", "settings.json")
				for _, hook := range left {
					result.SettingsLeft = append(result.SettingsLeft, settings+": "+boundedEnterpriseHookUserCleanupText(hook))
				}
				continue
			}
		}
		settings := filepath.Join(target.UserHome, ".claude", "settings.json")
		n, left, err := windowsManagedClaudeSettingsRemover(target.UserHome, target.SID, runtimeDir)
		if err != nil {
			result.Failed = append(result.Failed, "claudecode/"+target.SID+": "+boundedEnterpriseHookUserCleanupText(err.Error()))
			continue
		}
		if n > 0 {
			result.Removed = append(result.Removed, "claudecode/"+target.SID)
			// The result named only the per-user data a purge removed, so an
			// MDM report could not see that users' files were edited (#1290).
			result.SettingsEdited = append(result.SettingsEdited, fmt.Sprintf(
				"removed %d DefenseClaw hook command(s) from %s", n, settings))
		}
		// The leftovers come from the same settings transaction as the
		// removal, so a later read failure or a concurrent change cannot
		// hide one (#1286). Each names the hook event and the launcher, never
		// the command's arguments.
		for _, hook := range left {
			result.SettingsLeft = append(result.SettingsLeft, settings+": "+boundedEnterpriseHookUserCleanupText(hook))
		}
	}
	if identityErr != nil && blockedClaude && len(entries) == 0 {
		result.Failed = append(result.Failed,
			windowsManagedHooksRegistrationsNotRemovedPrefix+boundedEnterpriseHookUserCleanupText(identityErr.Error()))
	}
	if len(entries) == 0 {
		return result
	}
	if identityErr != nil {
		for _, entry := range entries {
			result.Pending = append(result.Pending, enterpriseHookUserCleanupLabel(entry))
		}
		result.Pending = windowsManagedHooksStandaloneRegistrationsLeft(entries, result.Pending)
		if len(result.Pending) > 0 {
			result.Failed = append(result.Failed,
				windowsManagedHooksRegistrationsNotRemovedPrefix+boundedEnterpriseHookUserCleanupText(identityErr.Error()))
		}
		return result
	}
	_, attempted := runEnterpriseHookUserCleanups(ctx, entries, enterpriseHookWindowsUserCleanupAttempt, now)
	result.Removed = append(result.Removed, attempted.Removed...)
	result.Pending = windowsManagedHooksStandaloneRegistrationsLeft(entries, append(result.Pending, attempted.Pending...))
	result.Failed = append(result.Failed, attempted.Failed...)
	return result
}

// windowsManagedHooksStandaloneRegistrationsLeft drops from the pending labels
// every entry whose user's agent configuration holds no DefenseClaw
// registration: there is nothing left to remove once the user signs in, so
// naming it in user_registrations_pending is wrong (GAP-2098: an enrolled
// OpenCode row without the plugin). An entry the read cannot tell about
// stays pending.
func windowsManagedHooksStandaloneRegistrationsLeft(entries []enterpriseHookUserCleanup, pending []string) []string {
	if len(pending) == 0 {
		return pending
	}
	byLabel := make(map[string]enterpriseHookUserCleanup, len(entries))
	for _, entry := range entries {
		byLabel[enterpriseHookUserCleanupLabel(entry)] = entry
	}
	left := make([]string, 0, len(pending))
	for _, label := range pending {
		if entry, ok := byLabel[label]; ok && windowsManagedHooksStandaloneRegistrationGone(enterprisehooks.ManifestTarget{
			User: entry.User, UserHome: entry.UserHome, SID: entry.SID, Connector: entry.Connector, DataDir: entry.DataDir,
		}) {
			continue
		}
		left = append(left, label)
	}
	return left
}
