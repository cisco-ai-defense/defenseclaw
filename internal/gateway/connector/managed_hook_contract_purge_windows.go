// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

// ClearManagedHookContractLockEntryForOwner removes one connector's stale
// contract identity during an authenticated machine purge. The shared lock and
// every peer connector entry remain intact.
func ClearManagedHookContractLockEntryForOwner(
	dataDir, connectorName, expectedOwnerSID string,
) error {
	if err := requireWindowsCodexMachineAdministrator(); err != nil {
		return fmt.Errorf("clear managed hook contract lock: %w", err)
	}
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" || !filepath.IsAbs(dataDir) ||
		filepath.Clean(dataDir) != dataDir ||
		!strings.EqualFold(filepath.Base(dataDir), ".defenseclaw") {
		return errors.New("managed hook contract data directory is not canonical")
	}
	connectorName = normalizeConnectorName(connectorName)
	switch connectorName {
	case "claudecode", "codex", "cursor":
	default:
		return fmt.Errorf("unsupported Windows managed connector %q", connectorName)
	}
	target, err := windows.StringToSid(strings.TrimSpace(expectedOwnerSID))
	if err != nil || !windowsManagedHookContractInteractiveUserSID(target) {
		return errors.New("managed hook contract owner SID is not an interactive user")
	}
	path := filepath.Join(dataDir, hookContractLockFile)
	if info, statErr := os.Lstat(path); errors.Is(statErr, os.ErrNotExist) {
		return nil
	} else if statErr != nil {
		return fmt.Errorf("inspect managed hook contract lock: %w", statErr)
	} else if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("managed hook contract lock is not a regular file")
	}

	return withFileLockModeForTarget(path, true, target, func() error {
		lock, err := loadManagedHookContractLockForOwner(dataDir, target.String())
		if err != nil {
			return fmt.Errorf("load managed hook contract lock for purge: %w", err)
		}
		if _, exists := lock.Connectors[connectorName]; !exists {
			return nil
		}
		delete(lock.Connectors, connectorName)
		if len(lock.Connectors) == 0 {
			lock.SharedHookScriptDigests = nil
		}
		previousTimes := []string{lock.UpdatedAt}
		for _, peer := range lock.Connectors {
			previousTimes = append(previousTimes, peer.UpdatedAt)
		}
		lock.UpdatedAt = nextHookContractTimestamp(time.Now(), previousTimes...)
		body, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			return err
		}
		if err := writeManagedTargetRuntimeFileForTarget(
			path,
			append(body, '\n'),
			true,
			target,
		); err != nil {
			return fmt.Errorf("write purged managed hook contract lock: %w", err)
		}
		stored, err := loadManagedHookContractLockForOwner(dataDir, target.String())
		if err != nil {
			return fmt.Errorf("verify purged managed hook contract lock: %w", err)
		}
		if _, exists := stored.Connectors[connectorName]; exists {
			return fmt.Errorf("managed hook contract lock retained %s after purge", connectorName)
		}
		return nil
	})
}

func windowsManagedHookContractInteractiveUserSID(target *windows.SID) bool {
	if target == nil || target.IsWellKnown(windows.WinLocalSystemSid) ||
		target.IsWellKnown(windows.WinLocalServiceSid) ||
		target.IsWellKnown(windows.WinNetworkServiceSid) ||
		target.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return false
	}
	sid := target.String()
	return strings.HasPrefix(sid, "S-1-5-21-") ||
		strings.HasPrefix(sid, "S-1-12-1-")
}
