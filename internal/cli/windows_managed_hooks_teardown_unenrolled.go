// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// windowsManagedHooksTeardownUnenrolledFromGuardian returns the failed
// targets the Guardian left out of the machine enrollment it published
// (windowsManagedHooksTeardownUnenrolledTargets), read from the same
// protected records windowsManagedHooksTargetsFromGuardian authenticated.
func windowsManagedHooksTeardownUnenrolledFromGuardian(
	runtimePath string,
	failed []windowsManagedHooksTeardownTarget,
) ([]windowsManagedHooksTeardownTarget, error) {
	if len(failed) == 0 {
		return []windowsManagedHooksTeardownTarget{}, nil
	}
	authorization, authorizationExists, err := loadEnterpriseHookGuardianAuthorization(runtimePath)
	if err != nil {
		return nil, fmt.Errorf("load protected Guardian authorization for teardown: %w", err)
	}
	state, stateExists, err := loadEnterpriseHookGuardianState(runtimePath)
	if err != nil {
		return nil, fmt.Errorf("load protected Guardian state for teardown: %w", err)
	}
	if !authorizationExists || !stateExists {
		return nil, fmt.Errorf("activated deployment is missing its protected Guardian activation evidence")
	}
	return windowsManagedHooksTeardownUnenrolledTargets(authorization, state, failed), nil
}

// windowsManagedHooksTeardownUnenrolledTargets returns the failed targets
// whose protection ledger row is absent: the Guardian publishes every
// enabled target except a failed one it never protected
// (enterpriseHookFailedTargetUnenrolls, the rule the reconcile and verify
// share since GAP-0790). The teardown expects exactly that published set.
// Before it expected every manifest target, so an account the Guardian
// skipped, such as one whose folder holds a per-user DefenseClaw install
// (GAP-1733), made every uninstall refuse until that install was removed
// (GAP-1892). A per-user-install tamper row is the row of a protected
// account and stays enrolled (GAP-1733 review 2), and a target the ledger
// names stays expected, so a protected account that lost its enrollment
// still fails the check.
func windowsManagedHooksTeardownUnenrolledTargets(
	authorization enterpriseHookGuardianAuthorization,
	state enterpriseHookGuardianState,
	failed []windowsManagedHooksTeardownTarget,
) []windowsManagedHooksTeardownTarget {
	rows := make(map[string]enterpriseHookReconcileRow, len(state.Results))
	for _, row := range state.Results {
		rows[enterpriseHookUnit(row.Connector, row.SID)] = row
	}
	unenrolled := make([]windowsManagedHooksTeardownTarget, 0, len(failed))
	for _, target := range failed {
		row, recorded := rows[enterpriseHookUnit(target.Connector, target.SID)]
		if !recorded || strings.HasPrefix(strings.TrimSpace(row.Error), enterpriseHookAccountPerUserInstallTamper) {
			continue
		}
		home := filepath.Dir(target.DataDir)
		protected := false
		for _, ledgerRow := range authorization.ProtectedTargets {
			if enterpriseHookRowMatches(ledgerRow, "", home, target.SID, target.Connector) {
				protected = true
				break
			}
		}
		if !protected {
			unenrolled = append(unenrolled, target)
		}
	}
	return unenrolled
}

// windowsManagedHooksTeardownWithoutUnenrolled drops the unenrolled targets
// from the machine-scope enrollment the teardown expects.
func windowsManagedHooksTeardownWithoutUnenrolled(
	unenrolled []windowsManagedHooksTeardownTarget,
	claude []string,
	codex []connector.WindowsCodexManagedRuntimeTarget,
	cursor []enterprisehooks.WindowsCursorManagedRuntimeTarget,
) ([]string, []connector.WindowsCodexManagedRuntimeTarget, []enterprisehooks.WindowsCursorManagedRuntimeTarget) {
	if len(unenrolled) == 0 {
		return claude, codex, cursor
	}
	left := func(connectorName, sid string) bool {
		return windowsManagedHooksTeardownTargetIn(
			windowsManagedHooksTeardownTarget{Connector: connectorName, SID: sid},
			unenrolled,
		)
	}
	keptClaude := make([]string, 0, len(claude))
	for _, sid := range claude {
		if !left("claudecode", sid) {
			keptClaude = append(keptClaude, sid)
		}
	}
	keptCodex := make([]connector.WindowsCodexManagedRuntimeTarget, 0, len(codex))
	for _, target := range codex {
		if !left("codex", target.SID) {
			keptCodex = append(keptCodex, target)
		}
	}
	keptCursor := make([]enterprisehooks.WindowsCursorManagedRuntimeTarget, 0, len(cursor))
	for _, target := range cursor {
		if !left("cursor", target.SID) {
			keptCursor = append(keptCursor, target)
		}
	}
	return keptClaude, keptCodex, keptCursor
}

// windowsManagedHooksTeardownEnrollmentWithinManifest reports whether one
// connector's machine enrollment in a teardown journal (its SIDs, and their
// data directories when the enrollment names them) is the manifest's
// targets of that connector less failed ones only (GAP-1892).
func windowsManagedHooksTeardownEnrollmentWithinManifest(
	targets, failed []windowsManagedHooksTeardownTarget,
	connectorName string,
	enrolledSIDs []string,
	enrolledDataDirs []string,
) bool {
	if enrolledDataDirs != nil && len(enrolledDataDirs) != len(enrolledSIDs) {
		return false
	}
	seen := make(map[string]bool, len(enrolledSIDs))
	for index, sid := range enrolledSIDs {
		key := strings.ToUpper(strings.TrimSpace(sid))
		if key == "" || seen[key] {
			return false
		}
		seen[key] = true
		found := false
		for _, target := range targets {
			if target.Connector == connectorName && strings.EqualFold(target.SID, sid) &&
				(enrolledDataDirs == nil || sameWindowsEnterprisePathCLI(enrolledDataDirs[index], target.DataDir)) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	for _, target := range targets {
		if target.Connector == connectorName && !seen[strings.ToUpper(target.SID)] &&
			!windowsManagedHooksTeardownTargetIn(target, failed) {
			return false
		}
	}
	return true
}

// windowsPerUserEnrollmentMatchesTeardown reports whether a per-user
// connector's machine enrollment is the one the teardown expects: every
// expected target that did not fail enrolled exactly, nothing outside the
// expected set, and a failed target either enrolled (the Guardian keeps a
// target it protected before) or not (it leaves out one it never protected,
// GAP-1892).
func windowsPerUserEnrollmentMatchesTeardown(
	connectorName string,
	current []enterprisehooks.WindowsPerUserManagedEnrollmentTarget,
	exists bool,
	want []enterprisehooks.WindowsPerUserManagedEnrollmentTarget,
	failed []windowsManagedHooksTeardownTarget,
) bool {
	expected := make(map[string]string, len(want))
	required := 0
	for _, target := range want {
		key := strings.ToUpper(target.SID)
		expected[key] = target.DataDir
		if !windowsManagedHooksTeardownTargetIn(
			windowsManagedHooksTeardownTarget{Connector: connectorName, SID: target.SID},
			failed,
		) {
			required++
		}
	}
	if required == len(want) {
		return exists == (len(want) != 0) && equalWindowsPerUserEnrollmentTargets(current, want)
	}
	if !exists {
		return required == 0
	}
	seen := make(map[string]bool, len(current))
	for _, entry := range current {
		key := strings.ToUpper(entry.SID)
		dataDir, ok := expected[key]
		if !ok || seen[key] || !sameWindowsEnterprisePathCLI(entry.DataDir, dataDir) {
			return false
		}
		seen[key] = true
	}
	for _, target := range want {
		if !seen[strings.ToUpper(target.SID)] && !windowsManagedHooksTeardownTargetIn(
			windowsManagedHooksTeardownTarget{Connector: connectorName, SID: target.SID},
			failed,
		) {
			return false
		}
	}
	return true
}
