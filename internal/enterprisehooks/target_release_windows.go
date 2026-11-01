// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// WindowsProtectedTargetFromOtherRelease reads, without writing, the
// protected hook-contract lock entry of one managed target and reports the
// DefenseClaw release that wrote it when that is another release than this
// binary. The guardian asks only after the target failed verification while
// its account is signed out: an upgrade renders new hooks that only the
// account's own Windows session can install, so the target waits for that
// account's next sign-in instead of failing the whole upgrade (GAP-0644).
// A lock that cannot be read, or one this release wrote, is not from
// another release; such a failure stays a failure. Both profiles: a Secure
// Client upgrade with a signed-out enrolled account failed the same way.
func WindowsProtectedTargetFromOtherRelease(opts InstallOptions) (string, bool, error) {
	lock, err := windowsProtectedTargetLock(opts)
	if err != nil {
		return "", false, err
	}
	written := strings.TrimSpace(lock.DefenseClawVersion)
	if written == "" || written == strings.TrimSpace(version.Current().BinaryVersion) {
		return "", false, nil
	}
	return written, true, nil
}

// WindowsProtectedTargetRunsEarlierHookMatrix reads, without writing, one
// managed target's agent config and reports that it holds the hook matrix an
// earlier release registered, which differs from this release's only by the
// fail_closed setting Setup added since
// (connector.HookRegistrationLacksOnlyFailClosed). The guardian asks only for
// a target another release protected that fails verification while its
// account has no active session: its earlier hooks still guard the account
// until the guardian upgrades them in that session (rel-1-0-5 GAP-2463).
func WindowsProtectedTargetRunsEarlierHookMatrix(opts InstallOptions) (bool, error) {
	target, err := resolveWindowsGenericManagedTarget(opts)
	if err != nil {
		return false, err
	}
	var earlier bool
	err = connector.WithUserHomeDir(target.home, func() error {
		var checkErr error
		earlier, checkErr = connector.HookRegistrationLacksOnlyFailClosed(target.conn, target.setup)
		return checkErr
	})
	return earlier, err
}

// WindowsProtectedTargetHookFailModeChange reads, without writing, one
// managed target's protected hook-contract lock entry and returns the hook
// fail mode it records and the one opts asks for, both canonical; locked is
// "" without an entry for the target's connector. An administrator who
// changes the hook fail mode makes every enrolled target fail verification,
// and the guardian asks only after one failed while its account has no
// active session (rel-1-0-4 GAP-0585): a change to open waits for the next
// sign-in, its hooks still failing closed, and a change to closed is
// rendered now, under a disconnected session or an S4U logon.
func WindowsProtectedTargetHookFailModeChange(opts InstallOptions) (locked, wanted string, err error) {
	lock, err := windowsProtectedTargetLock(opts)
	if err != nil {
		return "", "", err
	}
	wanted = canonicalHookFailMode(opts.HookFailMode)
	if lock.Connector == "" {
		return "", wanted, nil
	}
	return canonicalHookFailMode(lock.HookFailMode), wanted, nil
}

// windowsProtectedTargetLock reads, without writing, the protected
// hook-contract lock entry of one managed target; an entry for another
// connector reads as none.
func windowsProtectedTargetLock(opts InstallOptions) (connector.HookContractLockEntry, error) {
	home, _, err := validateWindowsEnterpriseHome(opts.UserHome, opts.OwnerSID)
	if err != nil {
		return connector.HookContractLockEntry{}, err
	}
	dataDir, err := resolveWindowsEnterpriseDataDir(home, opts.DataDir)
	if err != nil {
		return connector.HookContractLockEntry{}, err
	}
	name := strings.ToLower(strings.TrimSpace(opts.ConnectorName))
	lock, err := connector.LoadHookContractLockEntryForMode(dataDir, name, true)
	if err != nil || lock.Connector != name {
		return connector.HookContractLockEntry{}, err
	}
	return lock, nil
}

// WindowsSecureClientProfileProcess reports whether this guardian serves the
// Secure Client profile rather than the standalone one.
func WindowsSecureClientProfileProcess() bool {
	return !windowsEnterpriseStandaloneProcess()
}

// IsWindowsEnterpriseNotLocalSystem reports the refusal of a session or
// mutation check run outside LocalSystem, such as Setup's own verify as the
// elevated administrator, which cannot query another account's session.
func IsWindowsEnterpriseNotLocalSystem(err error) bool {
	return errors.Is(err, errWindowsEnterpriseNotLocalSystem)
}
