// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
)

// windowsEnterpriseStandaloneDeferredDataDirAbsent reports whether a pending
// proof may treat the data-directory validation error as "no runtime": only in
// a standalone process, and only when the directory itself does not exist.
// Reparse points, foreign owners, wrong types and every other inspection
// failure stay hard errors, and Secure Client keeps requiring the directory.
func windowsEnterpriseStandaloneDeferredDataDirAbsent(err error) bool {
	return windowsEnterpriseStandaloneProcess() && errors.Is(err, fs.ErrNotExist)
}

func requireWindowsEnterpriseDeferredTargetPendingPlatform(target ManifestTarget) error {
	if !target.IsEnabled() || !target.IsDeferred() {
		return errors.New("enterprise hooks: pending proof requires an enabled deferred manifest target")
	}
	connectorName := strings.ToLower(strings.TrimSpace(target.Connector))
	_, perUser := windowsStandalonePerUserConnector(connectorName)
	switch {
	case connectorName == "codex" || connectorName == "claudecode" || connectorName == "cursor":
	case perUser && windowsEnterpriseStandaloneProcess():
	default:
		return fmt.Errorf(
			"enterprise hooks: deferred pending proof does not support connector %q",
			target.Connector,
		)
	}
	home, targetSID, err := validateWindowsEnterpriseHome(target.UserHome, target.SID)
	if err != nil {
		return err
	}
	dataDir, err := resolveWindowsEnterpriseDataDir(home, target.DataDir)
	if err != nil {
		return err
	}
	if err := validateWindowsUserPathElement(dataDir, targetSID, true, true, true); err != nil {
		if !windowsEnterpriseStandaloneDeferredDataDirAbsent(err) {
			return fmt.Errorf(
				"enterprise hooks: deferred target data directory is untrusted: %w",
				err,
			)
		}
		// Standalone writes every discovered row deferred, including users
		// DefenseClaw has never touched. An absent canonical data directory
		// holds no runtime, so it proves the pending state as well as a
		// trusted empty one; the selector-absence proof below still runs.
	}
	hookExecutable, err := windowsEnterpriseHookExecutable()
	if err != nil {
		return err
	}
	hookExecutable = filepath.Clean(hookExecutable)
	if err := windowsEnterpriseHookTrustCheck(hookExecutable); err != nil {
		return fmt.Errorf(
			"enterprise hooks: deferred target hook executable trust check failed: %w",
			err,
		)
	}
	return verifyWindowsManagedRuntimeSelectorTargetAbsentPlatform(
		WindowsManagedRuntimeSelectorSnapshotOptions{
			Connector:      connectorName,
			TargetSID:      targetSID.String(),
			DataDir:        dataDir,
			HookExecutable: hookExecutable,
		},
	)
}
