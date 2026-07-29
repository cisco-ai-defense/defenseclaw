// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/hookruntime"
)

const (
	deferredUninstallCleanupSchemaVersion = 1
	deferredUninstallCleanupFileName      = "uninstall-cleanup.json"
	deferredUninstallCleanupAckFileName   = "uninstall-cleanup-ack.json"

	deferredCleanupStatusPending        = "pending-reboot"
	deferredCleanupStatusRuntimeRetired = "runtime-retired"
	deferredCleanupStatusSuperseded     = "superseded"
)

// deferredUninstallCleanupRecord is the additive handoff between a completed
// full uninstall, the post-reboot Setup cleanup action, and the narrow
// post-process cache finalizer. It binds every removable path to one exact
// uninstall transaction and to the genuine Windows boot on which uninstall
// completed.
type deferredUninstallCleanupRecord struct {
	SchemaVersion           int      `json:"schema_version"`
	Status                  string   `json:"status"`
	TransactionID           string   `json:"transaction_id"`
	UninstallBootIdentifier string   `json:"uninstall_boot_identifier"`
	CleanupBootIdentifier   string   `json:"cleanup_boot_identifier,omitempty"`
	RuntimeRoot             string   `json:"runtime_root"`
	LauncherPath            string   `json:"launcher_path"`
	StatePath               string   `json:"state_path"`
	RetiredLauncherPath     string   `json:"retired_launcher_path"`
	RetiredStatePath        string   `json:"retired_state_path"`
	LauncherSHA256          string   `json:"launcher_sha256"`
	LauncherSize            int64    `json:"launcher_size"`
	LauncherKind            string   `json:"launcher_kind"`
	HookPath                string   `json:"hook_path"`
	HookSHA256              string   `json:"hook_sha256"`
	LauncherSigned          bool     `json:"launcher_signed"`
	SignerThumbprintSHA256  string   `json:"signer_thumbprint_sha256,omitempty"`
	UnsignedLocalArtifact   bool     `json:"unsigned_local_artifact"`
	MaintenancePath         string   `json:"maintenance_path"`
	MaintenanceSHA256       string   `json:"maintenance_sha256"`
	InstallerStateRoot      string   `json:"installer_state_root"`
	JournalPath             string   `json:"journal_path"`
	RecordPath              string   `json:"record_path"`
	CacheAckPath            string   `json:"cache_ack_path"`
	RunValueName            string   `json:"run_value_name"`
	RunCommand              string   `json:"run_command"`
	VerifiedConnectors      []string `json:"verified_connectors"`
}

func deferredUninstallCleanupPath(transactionRoot string) string {
	return filepath.Join(transactionRoot, deferredUninstallCleanupFileName)
}

func deferredUninstallCleanupAckPath(maintenancePath string) string {
	return filepath.Join(filepath.Dir(maintenancePath), deferredUninstallCleanupAckFileName)
}

func retiredHookRuntimePath(path, transactionID string) string {
	return path + ".retired." + transactionID
}

func validBootIdentifier(value string) bool {
	if len(value) != 36 || value != strings.ToLower(value) {
		return false
	}
	for index, char := range value {
		switch index {
		case 8, 13, 18, 23:
			if char != '-' {
				return false
			}
		default:
			if !strings.ContainsRune("0123456789abcdef", char) {
				return false
			}
		}
	}
	return true
}

func validateDeferredUninstallCleanupRecord(
	record deferredUninstallCleanupRecord,
	paths hookruntime.Paths,
	transactionRoot, maintenancePath, runValueName, runCommand string,
) error {
	if record.SchemaVersion != deferredUninstallCleanupSchemaVersion {
		return fmt.Errorf("unsupported deferred uninstall cleanup schema %d", record.SchemaVersion)
	}
	switch record.Status {
	case deferredCleanupStatusPending, deferredCleanupStatusSuperseded:
		if record.CleanupBootIdentifier != "" {
			return errors.New("pending or superseded cleanup unexpectedly records a cleanup boot identifier")
		}
	case deferredCleanupStatusRuntimeRetired:
		if !validBootIdentifier(record.CleanupBootIdentifier) ||
			record.CleanupBootIdentifier == record.UninstallBootIdentifier {
			return errors.New("retired cleanup lacks a distinct valid cleanup boot identifier")
		}
	default:
		return fmt.Errorf("unsupported deferred uninstall cleanup status %q", record.Status)
	}
	if !validSetupTransactionID(record.TransactionID) {
		return errors.New("deferred uninstall cleanup has an invalid transaction identity")
	}
	if !validBootIdentifier(record.UninstallBootIdentifier) {
		return errors.New("deferred uninstall cleanup has an invalid uninstall boot identifier")
	}
	if !samePath(record.RuntimeRoot, paths.Root) ||
		!samePath(record.LauncherPath, paths.Launcher) ||
		!samePath(record.StatePath, paths.State) {
		return errors.New("deferred uninstall cleanup does not name the canonical HookRuntime paths")
	}
	if !samePath(record.RetiredLauncherPath, retiredHookRuntimePath(paths.Launcher, record.TransactionID)) ||
		!samePath(record.RetiredStatePath, retiredHookRuntimePath(paths.State, record.TransactionID)) {
		return errors.New("deferred uninstall cleanup has invalid retired HookRuntime paths")
	}
	if !validLowerSHA256(record.LauncherSHA256) ||
		record.LauncherSize <= 0 || record.LauncherSize > hookruntime.MaxHookLauncherBytes {
		return errors.New("deferred uninstall cleanup has an invalid launcher identity")
	}
	if record.LauncherKind != hookruntime.LauncherKindTrampoline ||
		!filepath.IsAbs(record.HookPath) ||
		filepath.Clean(record.HookPath) != record.HookPath ||
		!strings.EqualFold(filepath.Base(record.HookPath), hookruntime.LauncherName) ||
		!validLowerSHA256(record.HookSHA256) {
		return errors.New("deferred uninstall cleanup is not bound to the accepted trampoline interface")
	}
	if record.LauncherSigned {
		if record.UnsignedLocalArtifact || !validLowerSHA256(record.SignerThumbprintSHA256) {
			return errors.New("deferred uninstall cleanup has an invalid signed launcher policy")
		}
	} else if !record.UnsignedLocalArtifact || record.SignerThumbprintSHA256 != "" {
		return errors.New("deferred uninstall cleanup has an invalid unsigned-local launcher policy")
	}
	if !samePath(record.MaintenancePath, maintenancePath) ||
		!validLowerSHA256(record.MaintenanceSHA256) {
		return errors.New("deferred uninstall cleanup has an invalid maintenance executable identity")
	}
	expectedJournal := journalPaths(transactionRoot).Journal
	expectedRecord := deferredUninstallCleanupPath(transactionRoot)
	if !samePath(record.InstallerStateRoot, transactionRoot) ||
		!samePath(record.JournalPath, expectedJournal) ||
		!samePath(record.RecordPath, expectedRecord) ||
		!samePath(record.CacheAckPath, deferredUninstallCleanupAckPath(maintenancePath)) {
		return errors.New("deferred uninstall cleanup does not name the canonical installer-state paths")
	}
	if record.RunValueName != runValueName || record.RunCommand != runCommand {
		return errors.New("deferred uninstall cleanup does not match the owned startup command")
	}
	if len(record.VerifiedConnectors) > 2 || !slices.IsSorted(record.VerifiedConnectors) {
		return errors.New("deferred uninstall cleanup has an invalid verified connector set")
	}
	for index, connector := range record.VerifiedConnectors {
		if connector != "claudecode" && connector != "codex" {
			return fmt.Errorf("deferred uninstall cleanup has an invalid connector %q", connector)
		}
		if index > 0 && record.VerifiedConnectors[index-1] == connector {
			return errors.New("deferred uninstall cleanup repeats a verified connector")
		}
	}
	return nil
}
