// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

func requireWindowsEnterpriseDeferredTargetPendingPlatform(target ManifestTarget) error {
	if !target.IsEnabled() || !target.IsDeferred() {
		return errors.New("enterprise hooks: pending proof requires an enabled deferred manifest target")
	}
	connectorName := strings.ToLower(strings.TrimSpace(target.Connector))
	switch connectorName {
	case "codex", "claudecode", "cursor":
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
		return fmt.Errorf(
			"enterprise hooks: deferred target data directory is untrusted: %w",
			err,
		)
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

func requireWindowsEnterpriseTargetUnselectedPlatform(target ManifestTarget) error {
	if !target.IsEnabled() {
		return errors.New("enterprise hooks: selection proof requires an enabled manifest target")
	}
	connectorName := strings.ToLower(strings.TrimSpace(target.Connector))
	switch connectorName {
	case "codex", "claudecode", "cursor":
	default:
		return fmt.Errorf(
			"enterprise hooks: selection proof does not support connector %q",
			target.Connector,
		)
	}
	_, targetSID, err := validateWindowsEnterpriseHome(target.UserHome, target.SID)
	if err != nil {
		return err
	}
	selector, _, exists, err := readWindowsManagedRuntimeSelector(connectorName, true)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	if _, selected := windowsManagedRuntimeSelectorTargetForSID(selector, targetSID.String()); selected {
		return errors.New("enterprise hooks: target already has a selected managed runtime")
	}
	return nil
}
