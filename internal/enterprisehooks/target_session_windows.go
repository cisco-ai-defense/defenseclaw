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
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/windows"
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
	if err := windowsDeferredTargetDataDirExactCheck(dataDir, targetSID); err != nil {
		if healErr := healWindowsEnterpriseDeferredTargetDataDir(home, dataDir, targetSID, err); healErr != nil {
			return fmt.Errorf(
				"enterprise hooks: deferred target data directory is untrusted: %w",
				healErr,
			)
		}
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

// Seams for tests.
var (
	windowsDeferredTargetDataDirExactCheck = func(path string, target *windows.SID) error {
		return validateWindowsUserPathElement(path, target, true, true, true)
	}
	windowsDeferredTargetDataDirWriterCheck = func(path string, target *windows.SID) error {
		return validateWindowsUserPathElement(path, target, true, true, false)
	}
)

// windowsDeferredTargetAccepted holds the accepted findings already logged, so
// a guardian tick does not repeat an unchanged one.
var windowsDeferredTargetAccepted sync.Map

// healWindowsEnterpriseDeferredTargetDataDir handles a deferred (signed-out)
// target whose data directory is not at its exact per-user descriptor, as
// after an ACL reset of the profile folder. There is no user session to
// impersonate, so the LocalSystem guardian restores the canonical per-user
// DACL itself through the privileged no-follow repair: the owner stays the
// target user (an administrator or orphaned owner is handed back to it), and
// reparse points and hard links are refused before anything is written. The
// repair is logged once. When the descriptor still is not exact but no
// untrusted principal can write the folder, the drift is accepted and logged
// once instead of failing the target. Anything else, and every finding in
// strict mode, returns the original error.
func healWindowsEnterpriseDeferredTargetDataDir(home, dataDir string, target *windows.SID, driftErr error) error {
	if managed.TrustStrictAncestors() {
		return driftErr
	}
	var repairErr error
	if identityErr := windowsEnterpriseMutationIdentityCheck(); identityErr == nil {
		repairErr = windowsEnterpriseGuardianDACLRepair(home, dataDir, target, true)
		if repairErr == nil {
			recheck := windowsDeferredTargetDataDirExactCheck(dataDir, target)
			if recheck == nil {
				windowsDeferredTargetAccepted.Delete(strings.ToLower(filepath.Clean(dataDir)))
				managed.EmitResilienceEvent(managed.MarkerRepair, map[string]string{
					"sid":    target.String(),
					"path":   dataDir,
					"reason": "deferred target data directory: " + driftErr.Error(),
				})
				return nil
			}
			repairErr = fmt.Errorf("still not exact after repair: %w", recheck)
		}
	} else {
		repairErr = fmt.Errorf("repair needs the LocalSystem guardian: %w", identityErr)
	}
	if writerErr := windowsDeferredTargetDataDirWriterCheck(dataDir, target); writerErr != nil {
		return errors.Join(driftErr, writerErr)
	}
	reason := "deferred target data directory: " + driftErr.Error() + "; not repaired: " + repairErr.Error()
	key := strings.ToLower(filepath.Clean(dataDir))
	if previous, loaded := windowsDeferredTargetAccepted.Swap(key, reason); !loaded || previous != reason {
		managed.EmitResilienceEvent(managed.MarkerAccept, map[string]string{
			"sid":    target.String(),
			"path":   dataDir,
			"reason": reason,
		})
	}
	return nil
}
