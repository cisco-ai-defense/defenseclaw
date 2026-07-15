// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"fmt"
	"path/filepath"
)

func commitAtomicTransformV2ExistingPlatform(
	path string, snapshot atomicFileSnapshot, txn *atomicTransformV2Transaction,
) error {
	receipt := txn.receipt
	if receipt.Remove {
		return commitAtomicTransformV2ExistingRemovePlatform(path, snapshot, txn)
	}
	progress := func(boundary string) error {
		return runAtomicTransformPhaseHook(
			path, atomicTransformPhase("replace-"+boundary),
			atomicTransformV2HookState(txn.base, receipt),
		)
	}
	attempt, err := invokeAtomicTransformV2Replacement(txn.targetDir, receipt, nil)
	if err != nil {
		return err
	}
	switch attempt.Disposition {
	case atomicTransformV2ReplaceReadyForPublication:
		if err := flushAtomicTransformV2ReplacementForPublication(
			txn.targetDir, receipt, attempt.Observed, progress,
		); err != nil {
			return err
		}
		if err := repairAtomicTransformV2ReplacementShortName(
			txn.targetDir, filepath.Base(receipt.TargetPath), receipt.TombstoneName,
			receipt.TargetShortName, receipt.StageShortName,
			attempt.Observed.Target, attempt.Observed.Backup, progress,
		); err != nil {
			return err
		}
		return runAtomicTransformPhaseHook(
			path, atomicTransformPhasePublished, atomicTransformV2HookState(txn.base, receipt),
		)
	case atomicTransformV2ReplaceRetryUntouched, atomicTransformV2ReplaceRetryForeignLive:
		return fmt.Errorf("%w: ReplaceFileW retry disposition %d", errAtomicTransformConflict, attempt.Disposition)
	case atomicTransformV2ReplaceRestoreOldThenRetry:
		if err := restoreAtomicTransformV2Replace1177(txn.targetDir, receipt, attempt.Observed, progress); err != nil {
			return err
		}
		return fmt.Errorf("%w: ReplaceFileW 1177 restored Old", errAtomicTransformConflict)
	default:
		return fmt.Errorf("ambiguous ReplaceFileW outcome (%v): %s: %w", attempt.Code,
			atomicTransformV2ReplaceObservationSummary(receipt, attempt.Observed), errAtomicTransformConflict)
	}
}

// Removal has no replacement file for ReplaceFileW. Keep its exact, bound,
// no-replace detach protocol; replacement publication above never exposes this
// two-name window.
func commitAtomicTransformV2ExistingRemovePlatform(
	path string, snapshot atomicFileSnapshot, txn *atomicTransformV2Transaction,
) error {
	receipt := txn.receipt
	targetName := filepath.Base(receipt.TargetPath)
	if err := txn.targetDir.validate(); err != nil {
		return err
	}
	target, err := openAtomicTransformBoundFilePlatform(txn.targetDir.file, targetName, true)
	if err != nil {
		return errAtomicTransformConflict
	}
	closed := false
	defer func() {
		if !closed {
			_ = target.Close()
		}
	}()
	state, err := atomicTransformBoundStateFromOpen(target, targetName, atomicTransformMaxConfigBytes)
	if err != nil || !atomicTransformV2StateMatches(receipt.Old, state, true) ||
		!atomicTransformSnapshotMatchesState(snapshot, state) {
		return errAtomicTransformConflict
	}
	tomb, err := atomicTransformBoundInspect(txn.targetDir, receipt.TombstoneName, atomicTransformMaxConfigBytes)
	if err != nil {
		return err
	}
	if tomb.exists {
		return fmt.Errorf("compare-and-swap tombstone already exists")
	}
	if err := txn.targetDir.validate(); err != nil {
		return err
	}
	if err := renameAtomicTransformBoundFilePlatform(
		txn.targetDir.file, target, receipt.TombstoneName, false,
	); err != nil {
		return err
	}
	if err := txn.targetDir.validate(); err != nil {
		return fmt.Errorf("target parent detached during exact prior-config rename: %w", err)
	}
	if err := target.Close(); err != nil {
		return err
	}
	closed = true
	return runAtomicTransformPhaseHook(
		path, atomicTransformPhasePublished, atomicTransformV2HookState(txn.base, receipt),
	)
}
