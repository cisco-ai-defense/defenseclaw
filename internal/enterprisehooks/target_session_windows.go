// Copyright 2026 Cisco Systems, Inc. and its affiliates
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
	"unsafe"

	"golang.org/x/sys/windows"
)

func windowsEnterpriseTargetHasAnySessionPlatform(ownerSID string) (bool, error) {
	target, err := validateWindowsEnterpriseTargetSID(ownerSID)
	if err != nil {
		return false, err
	}
	var sessions *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &sessions, &count); err != nil {
		return false, fmt.Errorf("enterprise hooks: enumerate Windows sessions for target SID %s: %w", target, err)
	}
	if sessions != nil {
		defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(sessions)))
	}
	if count == 0 || sessions == nil {
		return false, nil
	}
	for _, session := range unsafe.Slice(sessions, count) {
		switch session.State {
		case windows.WTSActive, windows.WTSConnected, windows.WTSDisconnected:
		default:
			continue
		}
		var token windows.Token
		if err := windows.WTSQueryUserToken(session.SessionID, &token); err != nil {
			if errors.Is(err, windows.ERROR_NO_TOKEN) {
				continue
			}
			return false, fmt.Errorf("enterprise hooks: query session %d token for target SID %s: %w", session.SessionID, target, err)
		}
		user, err := token.GetTokenUser()
		token.Close()
		if err != nil {
			return false, fmt.Errorf("enterprise hooks: read session %d token user: %w", session.SessionID, err)
		}
		if user != nil && user.User.Sid != nil && user.User.Sid.Equals(target) {
			return true, nil
		}
	}
	return false, nil
}

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
	// A never-enrolled user has no data directory yet; only Install, under the
	// user's own token, creates it. Absence is proof enough. An existing one
	// must still pass the full owner/reparse validation.
	if _, statErr := os.Lstat(dataDir); statErr == nil {
		if err := validateWindowsUserPathElement(dataDir, targetSID, true, true, true); err != nil {
			return fmt.Errorf(
				"enterprise hooks: deferred target data directory is untrusted: %w",
				err,
			)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return fmt.Errorf(
			"enterprise hooks: inspect deferred target data directory: %w",
			statErr,
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
