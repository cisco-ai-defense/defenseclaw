// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"fmt"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The excluded-account marker is described in account_excluded_marker.go.
// These are its Windows bindings: administrator-only writes through the hook
// closure writer, and trusted reads through the managed policy reader.

func windowsAccountExcludedMarkerIO() accountExcludedMarkerIO {
	return accountExcludedMarkerIO{
		ensure: func(dir string) error { return windowsStandaloneHookClosureEnsure(dir) },
		write: func(path string, body []byte) error {
			return windowsStandaloneHookClosureWrite(path, body, true)
		},
		read:     readTrustedWindowsManagedPolicyFile,
		checkDir: func(dir string) error { return windowsManagedPolicyDirTrustCheck(dir) },
	}
}

// PublishWindowsExcludedAccountMarkers is the guardian step of an enumeration
// cycle: it makes the excluded-account markers exactly those of sids, the
// accounts the cycle judged excluded, and removes every other. Run as
// LocalSystem.
func PublishWindowsExcludedAccountMarkers(sids []string) error {
	layout, err := managed.StandaloneWindowsLayout()
	if err != nil {
		return err
	}
	return publishAccountExcludedMarkers(layout.HookRuntimeDir, sids, windowsAccountExcludedMarkerIO())
}

// WindowsCurrentAccountExcluded is the hook read: whether the guardian has
// published the account that runs this process as excluded from enrollment.
// A directory that is not trusted, a link, a damaged or unreadable marker, an
// absent marker and a token without a user SID are all "no".
func WindowsCurrentAccountExcluded() (bool, error) {
	sid := windowsCurrentProcessSID()
	if sid == nil {
		return false, fmt.Errorf("enterprise hooks: read the calling account SID")
	}
	layout, err := managed.StandaloneWindowsLayout()
	if err != nil {
		return false, err
	}
	return accountExcludedMarkerPresent(layout.HookRuntimeDir, sid.String(), windowsAccountExcludedMarkerIO())
}
