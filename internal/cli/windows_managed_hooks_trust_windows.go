// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Managed-hook lifecycle and teardown read protected state while the guardian
// is stopped, degraded, or skipping self-heal because a transaction is
// pending, so nothing else re-stamps these objects first. Permission drift is
// repaired here when the object has a canonical form, and what survives is
// accepted and logged on Secure Client: every file read below is
// schema-validated and the lifecycle files are hash-bound to the transaction.
// A standalone process refuses what survives, and repairs a file only when its
// bytes are the ones it last read while the file was trusted (GAP-0561). Structural failures
// (missing element, reparse point, hard link, wrong type, non-NTFS) stay
// fatal, and TrustStrictAncestorsEnv keeps every verdict fatal.
var (
	windowsManagedHooksEnsureCanonical = managed.EnsureCanonical
	windowsManagedHooksStrictFileCheck = managed.ValidateTrustedFilePath
	windowsManagedHooksStrictDirCheck  = managed.ValidateTrustedRuntimeDir
)

// validateWindowsManagedHooksTrustedFile validates a protected file the
// lifecycle or teardown reads. kind names the object's canonical form; pass
// windowsManagedHooksObjectKind(path) or "" when it has none.
//
// On standalone the repair runs only through managed.RepairWithContentProof:
// a repair restores the descriptor, not content an untrusted writer changed
// (GAP-0561 reviews 1 and 2).
func validateWindowsManagedHooksTrustedFile(path string, kind managed.ObjectKind, label string) error {
	needsProof := managed.StandaloneRepairNeedsProvenance()
	err := windowsManagedHooksStrictFileCheck(path, label)
	if err == nil {
		if needsProof {
			managed.RecordTrustedContent(path)
		}
		return nil
	}
	if managed.TrustStrictAncestors() {
		return err
	}
	repaired := false
	var ensureErr error
	repair := func() { repaired, ensureErr = repairWindowsManagedHooksObject(path, kind) }
	proven := true
	if needsProof {
		proven = managed.RepairWithContentProof(path, repair)
	} else {
		repair()
	}
	if ensureErr != nil {
		return errors.Join(err, ensureErr)
	}
	if proven && repaired && windowsManagedHooksStrictFileCheck(path, label) == nil {
		return nil
	}
	if needsProof {
		return err
	}
	return managed.ValidateTrustedPolicyFilePath(path, label)
}

// validateWindowsManagedHooksTeardownJournalFile validates the teardown
// journal. Unlike the lifecycle journal it carries no digest bound to
// protected transaction state, and rollback hands its snapshot bytes and
// descriptors to privileged restores, so drift is repaired to the canonical
// admin-file descriptor and the strict owner/DACL check must then pass:
// residual owner or writer drift after repair is fatal here.
//
// On standalone the repair runs only through managed.RepairWithContentProof
// (GAP-0561 reviews 1 and 2).
func validateWindowsManagedHooksTeardownJournalFile(path string) error {
	const label = "managed-hook teardown journal"
	needsProof := managed.StandaloneRepairNeedsProvenance()
	err := windowsManagedHooksStrictFileCheck(path, label)
	if err == nil {
		if needsProof {
			managed.RecordTrustedContent(path)
		}
		return nil
	}
	if managed.TrustStrictAncestors() {
		return err
	}
	var ensureErr error
	repair := func() { _, ensureErr = repairWindowsManagedHooksObject(path, managed.ObjectAdminFile) }
	if needsProof {
		if !managed.RepairWithContentProof(path, repair) {
			if ensureErr != nil {
				return errors.Join(err, ensureErr)
			}
			return err
		}
	} else {
		repair()
	}
	if ensureErr != nil {
		return errors.Join(err, ensureErr)
	}
	return windowsManagedHooksStrictFileCheck(path, label)
}

// validateWindowsManagedHooksTrustedDir is validateWindowsManagedHooksTrustedFile
// for a protected folder (the state root, a transaction directory).
func validateWindowsManagedHooksTrustedDir(path string, kind managed.ObjectKind, label string) error {
	err := windowsManagedHooksStrictDirCheck(path, label)
	if err == nil || managed.TrustStrictAncestors() {
		return err
	}
	if repaired, ensureErr := repairWindowsManagedHooksObject(path, kind); ensureErr != nil {
		return errors.Join(err, ensureErr)
	} else if repaired && windowsManagedHooksStrictDirCheck(path, label) == nil {
		return nil
	}
	return managed.ValidateTrustedRuntimeDirTolerant(path, label)
}

// repairWindowsManagedHooksObject stamps kind's canonical descriptor on path.
// EnsureCanonical logs the outcome itself (MarkerRepair, MarkerAccept or
// MarkerBoundary) and only returns an error for a structural failure.
func repairWindowsManagedHooksObject(path string, kind managed.ObjectKind) (bool, error) {
	if kind == "" {
		return false, nil
	}
	result, err := windowsManagedHooksEnsureCanonical(path, kind, managed.CanonicalOptions{})
	if err != nil {
		return false, err
	}
	return result.Outcome == managed.CanonicalRepaired, nil
}

// windowsManagedHooksObjectKind maps a lifecycle or teardown file to its
// managed.ManagedInstallLayout kind: the files directly in the state root's
// install folder and the hook-guardian manifest are admin files. Anything else
// (transaction snapshots and backups, the gateway executable) has no canonical
// form here and is only validated drift-tolerantly.
func windowsManagedHooksObjectKind(path string) managed.ObjectKind {
	parent := filepath.Base(filepath.Dir(path))
	switch {
	case strings.EqualFold(parent, "install"):
		return managed.ObjectAdminFile
	case strings.EqualFold(parent, "hook-guardian") && strings.EqualFold(filepath.Base(path), "targets.yaml"):
		return managed.ObjectAdminFile
	}
	return ""
}
