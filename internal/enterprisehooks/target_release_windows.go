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
	home, _, err := validateWindowsEnterpriseHome(opts.UserHome, opts.OwnerSID)
	if err != nil {
		return "", false, err
	}
	dataDir, err := resolveWindowsEnterpriseDataDir(home, opts.DataDir)
	if err != nil {
		return "", false, err
	}
	name := strings.ToLower(strings.TrimSpace(opts.ConnectorName))
	lock, err := connector.LoadHookContractLockEntryForMode(dataDir, name, true)
	if err != nil {
		return "", false, err
	}
	written := strings.TrimSpace(lock.DefenseClawVersion)
	if lock.Connector != name || written == "" ||
		written == strings.TrimSpace(version.Current().BinaryVersion) {
		return "", false, nil
	}
	return written, true, nil
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
