// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

// Standalone per-user connectors (Copilot, Antigravity, Devin, Hermes,
// OpenCode, Amp) are part of the managed-hook teardown only in a process
// pinned to the standalone profile. Their machine wiring is the per-user
// enrollment and runtime selector of each hook-binary connector, plus the
// Go-owned Copilot machine policy and public summary. After the uninstall
// commits, finalize also removes DefenseClaw's own registration or plugin
// from each user's agent configuration, as that user (see
// removeWindowsManagedHooksStandalonePerUserRegistrations). Per-user runtime
// files stay, like every other connector.

func windowsManagedHooksStandalonePerUserTarget(connectorName string) bool {
	_, perUser := enterprisehooks.IsWindowsStandalonePerUserConnector(connectorName)
	return perUser && enterprisehooks.WindowsStandaloneProcess()
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

func windowsManagedHooksStandalonePerUserConnectors(targets []windowsManagedHooksTeardownTarget) []string {
	seen := map[string]bool{}
	names := []string{}
	for _, target := range targets {
		if _, perUser := enterprisehooks.IsWindowsStandalonePerUserConnector(target.Connector); perUser && !seen[target.Connector] {
			seen[target.Connector] = true
			names = append(names, target.Connector)
		}
	}
	sort.Strings(names)
	return names
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
		return nil
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
	_, err = enterprisepolicy.PurgeWindowsUnrecordedClaudeVersionFloor(
		enterprisepolicy.LayoutOptions(layout, programFiles, programData),
	)
	return err
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

func verifyWindowsManagedHooksStandalonePerUserClean(targets []windowsManagedHooksTeardownTarget) error {
	connectors := windowsManagedHooksStandalonePerUserConnectors(targets)
	if enterprisehooks.WindowsStandaloneProcess() {
		connectors = enterprisehooks.WindowsStandalonePerUserConnectorNames()
	}
	for _, connectorName := range connectors {
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
// were not deferred. Deferred rows the guardian never protected have
// nothing to remove.
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
		if !target.IsEnabled() || target.IsDeferred() {
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

// removeWindowsManagedHooksStandalonePerUserRegistrations runs, after a
// committed uninstall, each per-user connector's teardown as the user for
// every registration DefenseClaw made. It is best effort: the uninstall has
// already revoked every enrollment, so a leftover registration can no longer
// reach a gateway. Users without an active session, and every user when the
// uninstall does not run as LocalSystem (an interactive administrator
// cannot obtain another user's token), are reported as pending; there is no
// guardian left to clean them at their next sign-in.
func removeWindowsManagedHooksStandalonePerUserRegistrations(
	ctx context.Context,
	runtimeDir string,
	manifest enterprisehooks.Manifest,
) enterpriseHookUserCleanupResult {
	now := time.Now()
	entries, problems := windowsManagedHooksStandaloneUserCleanups(runtimeDir, manifest, now)
	result := enterpriseHookUserCleanupResult{Failed: problems}
	if len(entries) == 0 {
		return result
	}
	if err := enterpriseHookWindowsUserCleanupIdentity(); err != nil {
		for _, entry := range entries {
			result.Pending = append(result.Pending, enterpriseHookUserCleanupLabel(entry))
		}
		result.Failed = append(result.Failed,
			"per-user registrations were not removed: "+boundedEnterpriseHookUserCleanupText(err.Error()))
		return result
	}
	_, attempted := runEnterpriseHookUserCleanups(ctx, entries, enterpriseHookWindowsUserCleanupAttempt, now)
	result.Removed = attempted.Removed
	result.Pending = attempted.Pending
	result.Failed = append(result.Failed, attempted.Failed...)
	return result
}
