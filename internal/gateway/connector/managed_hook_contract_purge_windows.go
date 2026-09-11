// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

const WindowsManagedHookContractCleanupClaimSchema = 1

// ErrWindowsManagedHookContractCleanupSuperseded indicates that the exact
// connector entry captured by a retired deployment has been replaced. Callers
// must preserve the current entry rather than treating unrelated error text as
// proof that a newer deployment owns it.
var ErrWindowsManagedHookContractCleanupSuperseded = errors.New(
	"managed hook contract cleanup claim conflicts with a replacement connector entry",
)

// WindowsManagedHookContractCleanupClaim is a secretless compare-and-swap
// claim for one connector entry in a target-owned hook contract lock. The
// digest covers the complete connector-scoped entry, including its stable
// UpdatedAt identity, but deliberately excludes the shared lock's mutable
// global UpdatedAt field. A later install can therefore update a peer without
// invalidating this claim, while replacement of this connector fails closed.
type WindowsManagedHookContractCleanupClaim struct {
	SchemaVersion      int    `json:"schema_version"`
	Connector          string `json:"connector"`
	SID                string `json:"sid"`
	DataDir            string `json:"data_dir"`
	GatewayServiceName string `json:"gateway_service_name"`
	EntryPresent       bool   `json:"entry_present"`
	EntrySHA256        string `json:"entry_sha256"`
	Superseded         bool   `json:"superseded,omitempty"`
	ApplicationStarted bool   `json:"application_started,omitempty"`
	Completed          bool   `json:"completed,omitempty"`
}

// WindowsManagedHookContractCleanupResult describes one idempotent claim
// application. AlreadyAbsent is true only when no current connector entry
// remains; a mismatched entry is returned as an error and is never changed.
type WindowsManagedHookContractCleanupResult struct {
	Removed       bool
	AlreadyAbsent bool
	Superseded    bool
}

// CaptureManagedHookContractCleanupClaimForOwner authenticates the exact
// target-owned lock and captures only the connector entry's canonical digest.
// No token or other credential material is copied into administrator state.
func CaptureManagedHookContractCleanupClaimForOwner(
	dataDir, connectorName, expectedOwnerSID, expectedGatewayServiceName string,
) (WindowsManagedHookContractCleanupClaim, error) {
	if err := requireWindowsCodexMachineAdministrator(); err != nil {
		return WindowsManagedHookContractCleanupClaim{}, fmt.Errorf(
			"capture managed hook contract cleanup claim: %w",
			err,
		)
	}
	claim, target, err := validateWindowsManagedHookContractCleanupTarget(
		dataDir,
		connectorName,
		expectedOwnerSID,
		expectedGatewayServiceName,
	)
	if err != nil {
		return claim, err
	}
	path := filepath.Join(claim.DataDir, hookContractLockFile)
	if info, statErr := os.Lstat(path); errors.Is(statErr, os.ErrNotExist) {
		return claim, nil
	} else if statErr != nil {
		return claim, fmt.Errorf("inspect managed hook contract lock: %w", statErr)
	} else if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return claim, errors.New("managed hook contract lock is not a regular file")
	}
	err = withFileLockModeForTarget(path, true, target, func() error {
		lock, loadErr := loadManagedHookContractLockForOwner(claim.DataDir, claim.SID)
		if loadErr != nil {
			return fmt.Errorf("load managed hook contract lock for cleanup claim: %w", loadErr)
		}
		entry, exists := lock.Connectors[claim.Connector]
		if !exists {
			return nil
		}
		// Legacy pre-binding entries have an empty ManagedGatewayServiceName.
		// Teardown must still be able to remove such an entry, so treat empty
		// as "no binding pin" and capture the SHA256 for CAS-safe removal by
		// the apply path. A non-empty invalid value is still fail-closed.
		legacyEntry := strings.TrimSpace(entry.ManagedGatewayServiceName) == ""
		if !legacyEntry {
			if err := ValidateWindowsManagedGatewayServiceName(
				entry.ManagedGatewayServiceName,
			); err != nil {
				return fmt.Errorf(
					"managed hook contract entry has no valid gateway service binding: %w",
					err,
				)
			}
			if !strings.EqualFold(entry.ManagedGatewayServiceName, claim.GatewayServiceName) {
				claim.Superseded = true
				return nil
			}
		}
		digest, digestErr := windowsManagedHookContractEntrySHA256(entry)
		if digestErr != nil {
			return digestErr
		}
		claim.EntryPresent = true
		claim.EntrySHA256 = digest
		return nil
	})
	return claim, err
}

// ApplyManagedHookContractCleanupClaimForOwner removes only the entry captured
// by claim. The target file is locked and reauthenticated before its current
// connector entry is hashed, so a replacement entry or ownership/link drift
// cannot be mistaken for the retired deployment's state.
func ApplyManagedHookContractCleanupClaimForOwner(
	claim WindowsManagedHookContractCleanupClaim,
) (WindowsManagedHookContractCleanupResult, error) {
	return ApplyManagedHookContractCleanupClaimForOwnerWithBarrier(claim, nil)
}

// ApplyManagedHookContractCleanupClaimForOwnerWithBarrier invokes
// beforeMutation after the current entry matches the claim but while the
// connector lock remains held. Callers use that boundary to durably mark a
// claim in-progress before deletion, closing the crash/reinstall ambiguity.
func ApplyManagedHookContractCleanupClaimForOwnerWithBarrier(
	claim WindowsManagedHookContractCleanupClaim,
	beforeMutation func() error,
) (WindowsManagedHookContractCleanupResult, error) {
	var result WindowsManagedHookContractCleanupResult
	if err := requireWindowsCodexMachineAdministrator(); err != nil {
		return result, fmt.Errorf("apply managed hook contract cleanup claim: %w", err)
	}
	validated, target, err := validateWindowsManagedHookContractCleanupTarget(
		claim.DataDir,
		claim.Connector,
		claim.SID,
		claim.GatewayServiceName,
	)
	if err != nil {
		return result, err
	}
	if claim.SchemaVersion != validated.SchemaVersion ||
		claim.Connector != validated.Connector || claim.SID != validated.SID ||
		claim.DataDir != validated.DataDir ||
		claim.GatewayServiceName != validated.GatewayServiceName ||
		(claim.EntryPresent && !validManagedHookContractEntrySHA256(claim.EntrySHA256)) ||
		(!claim.EntryPresent && claim.EntrySHA256 != "") ||
		(!claim.EntryPresent && claim.ApplicationStarted) ||
		(claim.Superseded && (claim.EntryPresent || claim.ApplicationStarted)) {
		return result, errors.New("managed hook contract cleanup claim is noncanonical")
	}
	if claim.Superseded {
		result.Superseded = true
		return result, nil
	}
	if !claim.EntryPresent {
		result.AlreadyAbsent = true
		return result, nil
	}
	path := filepath.Join(claim.DataDir, hookContractLockFile)
	if info, statErr := os.Lstat(path); errors.Is(statErr, os.ErrNotExist) {
		if !claim.ApplicationStarted {
			return result, errors.New(
				"managed hook contract lock disappeared before the cleanup mutation barrier",
			)
		}
		result.AlreadyAbsent = true
		return result, nil
	} else if statErr != nil {
		return result, fmt.Errorf("inspect managed hook contract lock: %w", statErr)
	} else if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return result, errors.New("managed hook contract lock is not a regular file")
	}

	err = withFileLockModeForTarget(path, true, target, func() error {
		lock, loadErr := loadManagedHookContractLockForOwner(claim.DataDir, claim.SID)
		if loadErr != nil {
			return fmt.Errorf("load managed hook contract lock for cleanup: %w", loadErr)
		}
		entry, exists := lock.Connectors[claim.Connector]
		if !exists {
			if !claim.ApplicationStarted {
				return errors.New(
					"managed hook contract entry disappeared before the cleanup mutation barrier",
				)
			}
			result.AlreadyAbsent = true
			return nil
		}
		currentSHA256, digestErr := windowsManagedHookContractEntrySHA256(entry)
		if digestErr != nil {
			return digestErr
		}
		if currentSHA256 != claim.EntrySHA256 {
			return ErrWindowsManagedHookContractCleanupSuperseded
		}
		if beforeMutation != nil {
			if barrierErr := beforeMutation(); barrierErr != nil {
				return fmt.Errorf("persist managed hook contract cleanup mutation barrier: %w", barrierErr)
			}
		}
		delete(lock.Connectors, claim.Connector)
		if len(lock.Connectors) == 0 {
			lock.SharedHookScriptDigests = nil
		}
		previousTimes := []string{lock.UpdatedAt}
		for _, peer := range lock.Connectors {
			previousTimes = append(previousTimes, peer.UpdatedAt)
		}
		lock.UpdatedAt = nextHookContractTimestamp(time.Now(), previousTimes...)
		body, marshalErr := json.MarshalIndent(lock, "", "  ")
		if marshalErr != nil {
			return marshalErr
		}
		if writeErr := writeManagedTargetRuntimeFileForTarget(
			path,
			append(body, '\n'),
			true,
			target,
		); writeErr != nil {
			return fmt.Errorf("write cleaned managed hook contract lock: %w", writeErr)
		}
		stored, verifyErr := loadManagedHookContractLockForOwner(claim.DataDir, claim.SID)
		if verifyErr != nil {
			return fmt.Errorf("verify cleaned managed hook contract lock: %w", verifyErr)
		}
		if _, exists := stored.Connectors[claim.Connector]; exists {
			return fmt.Errorf("managed hook contract lock retained %s after cleanup", claim.Connector)
		}
		result.Removed = true
		return nil
	})
	return result, err
}

// ClearManagedHookContractLockEntryForOwner removes one connector's stale
// contract identity during an authenticated machine purge. The shared lock and
// every peer connector entry remain intact.
//
// CROSS-USER PRIVILEGE CONTRACT: Callers running as LocalSystem against a
// target-owned protected file MUST wrap this call in
// enterprisehooks.RunWithWindowsAdministratorOwnerRestorePrivilege. Writing a
// file whose owner differs from the caller's SID requires SeRestorePrivilege
// (ERROR_ACCESS_DENIED otherwise). The connector package cannot import
// enterprisehooks; the privilege is only present on threads created by the
// enterprisehooks helper.
func ClearManagedHookContractLockEntryForOwner(
	dataDir, connectorName, expectedOwnerSID, expectedGatewayServiceName string,
) error {
	claim, err := CaptureManagedHookContractCleanupClaimForOwner(
		dataDir,
		connectorName,
		expectedOwnerSID,
		expectedGatewayServiceName,
	)
	if err != nil {
		return err
	}
	_, err = ApplyManagedHookContractCleanupClaimForOwner(claim)
	return err
}

func validateWindowsManagedHookContractCleanupTarget(
	dataDir, connectorName, expectedOwnerSID, expectedGatewayServiceName string,
) (WindowsManagedHookContractCleanupClaim, *windows.SID, error) {
	claim := WindowsManagedHookContractCleanupClaim{
		SchemaVersion:      WindowsManagedHookContractCleanupClaimSchema,
		Connector:          normalizeConnectorName(connectorName),
		SID:                strings.TrimSpace(expectedOwnerSID),
		DataDir:            strings.TrimSpace(dataDir),
		GatewayServiceName: strings.TrimSpace(expectedGatewayServiceName),
	}
	if claim.DataDir == "" || !filepath.IsAbs(claim.DataDir) ||
		filepath.Clean(claim.DataDir) != claim.DataDir ||
		!strings.EqualFold(filepath.Base(claim.DataDir), ".defenseclaw") {
		return claim, nil, errors.New("managed hook contract data directory is not canonical")
	}
	switch claim.Connector {
	case "claudecode", "codex", "cursor":
	default:
		return claim, nil, fmt.Errorf("unsupported Windows managed connector %q", claim.Connector)
	}
	if err := ValidateWindowsManagedGatewayServiceName(
		claim.GatewayServiceName,
	); err != nil {
		return claim, nil, fmt.Errorf("managed hook contract cleanup gateway service: %w", err)
	}
	target, err := windows.StringToSid(claim.SID)
	if err != nil || !windowsManagedHookContractInteractiveUserSID(target) ||
		target.String() != claim.SID {
		return claim, nil, errors.New("managed hook contract owner SID is not a canonical interactive user")
	}
	return claim, target, nil
}

func windowsManagedHookContractEntrySHA256(entry HookContractLockEntry) (string, error) {
	body, err := json.Marshal(entry)
	if err != nil {
		return "", fmt.Errorf("marshal managed hook contract entry CAS: %w", err)
	}
	digest := sha256.Sum256(body)
	return fmt.Sprintf("sha256:%x", digest[:]), nil
}

func validManagedHookContractEntrySHA256(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 ||
		!strings.HasPrefix(value, "sha256:") || value != strings.ToLower(value) {
		return false
	}
	for _, char := range strings.TrimPrefix(value, "sha256:") {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
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
