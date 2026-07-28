// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/sys/windows"
)

const (
	atomicTransformV2Version        = 2
	atomicTransformV2Allocation     = "allocation"
	atomicTransformV2Staging        = "staging"
	atomicTransformV2Prepared       = "prepared"
	atomicTransformV2Terminal       = "terminal"
	atomicTransformV2Complete       = "complete"
	atomicTransformV2DecisionCommit = "commit"
	atomicTransformV2DecisionAbort  = "abort"
	atomicTransformV2ReceiptPrefix  = ".defenseclaw-cas-v2-"
	atomicTransformV2NamePrefix     = ".tmp-cas-v2-"
	atomicTransformV2MarkerVersion  = "DefenseClaw harmless CAS marker v2"
)

type atomicTransformV2Artifact struct {
	Name                     string `json:"name"`
	Identity                 string `json:"identity"`
	SHA256                   string `json:"sha256"`
	Size                     int64  `json:"size"`
	Mode                     uint32 `json:"mode"`
	ProtectionSHA256         string `json:"protection_sha256,omitempty"`
	MetadataSHA256           string `json:"metadata_sha256,omitempty"`
	PreservedMetadataSHA256  string `json:"preserved_metadata_sha256,omitempty"`
	StageOwnedMetadataSHA256 string `json:"stage_owned_metadata_sha256,omitempty"`
	OwnerGroupSHA256         string `json:"owner_group_sha256,omitempty"`
	CreationTime             uint64 `json:"creation_time,omitempty"`
	LastWriteTime            uint64 `json:"last_write_time,omitempty"`
	LinkCount                uint32 `json:"link_count,omitempty"`
}

type atomicTransformV2Receipt struct {
	Version              int                       `json:"version"`
	Phase                string                    `json:"phase"`
	TransactionID        string                    `json:"transaction_id"`
	LogicalPath          string                    `json:"logical_path"`
	InputPath            string                    `json:"input_path"`
	StateDir             string                    `json:"state_dir"`
	StateDirIdentity     string                    `json:"state_dir_identity"`
	TargetPath           string                    `json:"target_path"`
	TargetShortName      string                    `json:"target_short_name,omitempty"`
	StageShortName       string                    `json:"stage_short_name,omitempty"`
	TargetParentIdentity string                    `json:"target_parent_identity"`
	OldExists            bool                      `json:"old_exists"`
	Remove               bool                      `json:"remove"`
	RequestedPrivate     bool                      `json:"requested_private,omitempty"`
	Old                  atomicTransformV2Artifact `json:"old,omitempty"`
	Stage                atomicTransformV2Artifact `json:"stage,omitempty"`
	StageFinalName       string                    `json:"stage_final_name,omitempty"`
	StageMarker          atomicTransformV2Artifact `json:"stage_marker,omitempty"`
	FinalMarker          atomicTransformV2Artifact `json:"final_marker,omitempty"`
	TombstoneName        string                    `json:"tombstone_name,omitempty"`
	TerminalMarkerName   string                    `json:"terminal_marker_name"`
	TerminalMarker       atomicTransformV2Artifact `json:"terminal_marker"`
	StagingReceiptID     string                    `json:"staging_receipt_identity,omitempty"`
	PreparedReceiptID    string                    `json:"prepared_receipt_identity,omitempty"`
	TerminalReceiptID    string                    `json:"terminal_receipt_identity,omitempty"`
	Decision             string                    `json:"decision,omitempty"`
}

type atomicTransformV2PhaseReceipt struct {
	path    string
	gcPath  string
	receipt atomicTransformV2Receipt
	state   atomicTransformArtifactState
	exists  bool
	retired bool
	located bool
}

type atomicTransformV2Loaded struct {
	base       string
	logical    string
	receipt    atomicTransformV2Receipt
	allocation atomicTransformV2PhaseReceipt
	staging    atomicTransformV2PhaseReceipt
	prepared   atomicTransformV2PhaseReceipt
	terminal   atomicTransformV2PhaseReceipt
	complete   atomicTransformV2PhaseReceipt
	exists     bool
	gcOnly     bool
}

type atomicTransformV2Transaction struct {
	receipt         atomicTransformV2Receipt
	base            string
	allocationState atomicTransformArtifactState
	stagingState    atomicTransformArtifactState
	preparedState   atomicTransformArtifactState
	targetDir       *atomicTransformBoundDirectory
	stateDir        *atomicTransformBoundDirectory
}

func (txn *atomicTransformV2Transaction) close() error {
	if txn == nil {
		return nil
	}
	var errs []error
	if txn.targetDir != nil {
		errs = append(errs, txn.targetDir.Close())
		txn.targetDir = nil
	}
	if txn.stateDir != nil {
		errs = append(errs, txn.stateDir.Close())
		txn.stateDir = nil
	}
	return errors.Join(errs...)
}

func atomicTransformFileV2(
	path string,
	transactionDir string,
	perm os.FileMode,
	transform func(current []byte, exists bool) (atomicTransformResult, error),
) error {
	if err := atomicTransformValidateNoReparsePathPlatform(transactionDir); err != nil {
		return fmt.Errorf("validate Windows transaction locator: %w", err)
	}
	stateDir, err := prepareAtomicTransformStateDir(transactionDir)
	if err != nil {
		return fmt.Errorf("prepare stable compare-and-swap transaction directory: %w", err)
	}
	if err := atomicTransformValidateNoReparsePathPlatform(stateDir); err != nil {
		return fmt.Errorf("revalidate Windows transaction locator: %w", err)
	}
	return withAtomicTransformV2ProtocolLock(path, stateDir, func() error {
		return recoverAtomicTransformV2Locked(path, stateDir)
	}, func(target string) error {
		// Pin the canonical physical target spelling for the complete locked
		// operation. In particular, an existing 8.3 leaf alias can stop resolving
		// after replacement gives the new inode a different short-name binding.
		// Re-resolving the caller's alias between snapshot, commit, and recovery
		// would then manufacture a conflict despite exclusive protocol ownership.
		return atomicTransformFileV2Locked(path, target, stateDir, perm, transform)
	})
}

func atomicTransformFileV2Locked(
	inputPath, path, stateDir string,
	perm os.FileMode,
	transform func(current []byte, exists bool) (atomicTransformResult, error),
) error {
	for attempt := 0; attempt < atomicTransformMaxAttempts; attempt++ {
		if err := recoverAtomicTransformV2Locked(inputPath, stateDir); err != nil {
			return fmt.Errorf("recover interrupted config transform for %s: %w", path, err)
		}
		if err := prepareAtomicTransformV2TargetParent(path); err != nil {
			return err
		}
		snapshot, err := readAtomicFileSnapshot(path)
		if err != nil {
			return err
		}
		result, err := transform(append([]byte(nil), snapshot.data...), snapshot.exists)
		if err != nil {
			matches, compareErr := atomicFileSnapshotStillMatches(path, snapshot)
			if compareErr != nil {
				return errors.Join(err, compareErr)
			}
			if !matches {
				continue
			}
			return err
		}
		writePerm := result.Perm
		if writePerm == 0 {
			writePerm = perm
		}
		if !result.Remove && len(result.Data) > atomicTransformMaxConfigBytes {
			return fmt.Errorf("transformed config exceeds %d-byte compare-and-swap limit", atomicTransformMaxConfigBytes)
		}
		semanticNoop := (!snapshot.exists && result.Remove) ||
			(snapshot.exists && !result.Remove && bytes.Equal(snapshot.data, result.Data) &&
				atomicTransformSnapshotSatisfiesPermissions(snapshot, writePerm))
		runAtomicTransformBeforeCompareHook(path, attempt)
		matches, err := atomicFileSnapshotStillMatches(path, snapshot)
		if err != nil {
			return err
		}
		if !matches {
			continue
		}
		if snapshot.exists && !result.Remove {
			changed, convergeErr := convergeAtomicTransformV2ExistingProtection(path, writePerm, snapshot)
			if convergeErr != nil {
				return fmt.Errorf("converge existing config protection before transaction receipt: %w", convergeErr)
			}
			if changed {
				// The exact pre-receipt destination changed metadata. Restart from
				// a new snapshot so Old, Ra, and Rp all authenticate the converged
				// protection rather than the unsafe predecessor.
				continue
			}
		}
		if semanticNoop {
			return nil
		}

		txn, err := beginAtomicTransformV2(inputPath, path, stateDir, snapshot, result, writePerm)
		if err != nil {
			_ = txn.close()
			if recoverErr := recoverAtomicTransformV2Locked(inputPath, stateDir); recoverErr != nil {
				return errors.Join(err, recoverErr)
			}
			if errors.Is(err, errAtomicTransformConflict) {
				continue
			}
			return err
		}
		runAtomicTransformBeforeCommitHook(path, attempt)
		matches, err = atomicFileSnapshotStillMatches(path, snapshot)
		if err != nil || !matches {
			_ = txn.close()
			recoverErr := recoverAtomicTransformV2Locked(inputPath, stateDir)
			if recoverErr != nil {
				if err != nil {
					return errors.Join(err, recoverErr)
				}
				return recoverErr
			}
			if err != nil {
				return err
			}
			continue
		}

		err = commitAtomicTransformV2(path, snapshot, txn)
		if closeErr := txn.close(); closeErr != nil && err == nil {
			err = closeErr
		}
		if err != nil {
			recoverErr := recoverAtomicTransformV2Locked(inputPath, stateDir)
			if recoverErr != nil {
				return errors.Join(err, recoverErr)
			}
			if errors.Is(err, errAtomicTransformConflict) {
				continue
			}
			return err
		}
		if err := recoverAtomicTransformV2Locked(inputPath, stateDir); err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf(
		"config %s changed during each of %d read/merge attempts; refusing to overwrite concurrent edits",
		inputPath,
		atomicTransformMaxAttempts,
	)
}

func withAtomicTransformV2ProtocolLock(
	path, stateDir string, beforeResolve func() error, fn func(target string) error,
) error {
	stateBound, err := bindAtomicTransformDirectory(stateDir)
	if err != nil {
		return err
	}
	defer stateBound.Close()
	if err := stateBound.validatePrivate(); err != nil {
		return err
	}
	if !atomicTransformPathsEqual(stateDir, stateBound.path) {
		return fmt.Errorf("stable compare-and-swap state locator is an alias; use its canonical non-reparse path")
	}
	// Acquire the namespace-global lock before resolving or binding the target.
	// Otherwise a waiter can resolve an 8.3 locator while the current owner has
	// temporarily detached the live leaf, cache that transient spelling, and
	// mutate the wrong name after eventually acquiring the lock. The protected
	// canonical state directory is independent of target locator spelling, so it
	// is the only safe namespace in which to serialize resolution itself.
	return withAtomicTransformBoundProtocolLock(stateBound, ".defenseclaw-v2-protocol.lock", func() error {
		// Recovery must scan receipts by the normalized input locator before this
		// process resolves the target. A crash while restoring an 8.3 short-name
		// binding can make that locator temporarily absent; its receipt is the
		// durable authority for repairing the binding and recovering the pinned
		// long target.
		if beforeResolve != nil {
			if err := beforeResolve(); err != nil {
				return err
			}
		}
		// Recovery-only callers stop here. Terminal, complete, and cleanup-only
		// receipts are bound to their authenticated TargetPath/parent and never
		// inspect live. An operator may therefore replace the live leaf with a
		// reparse point after P without blocking receipt convergence. A caller
		// starting a new transform always supplies fn and remains subject to the
		// strict full-path no-reparse gate below.
		if fn == nil {
			return nil
		}
		if err := atomicTransformValidateNoReparsePathPlatform(path); err != nil {
			return fmt.Errorf("revalidate Windows config locator under protocol lock: %w", err)
		}
		if err := prepareAtomicTransformV2TargetParent(path); err != nil {
			return err
		}
		resolved, err := resolveAtomicWritePath(path)
		if err != nil {
			return err
		}
		target, err := canonicalAtomicTransformTargetPath(resolved)
		if err != nil {
			return err
		}
		targetDir, err := bindAtomicTransformDirectory(filepath.Dir(target))
		if err != nil {
			return err
		}
		defer targetDir.Close()
		if err := atomicTransformValidateStableVolumeLocatorPlatform(path, targetDir); err != nil {
			return err
		}
		return fn(target)
	})
}

func prepareAtomicTransformV2TargetParent(path string) error {
	target, err := resolveAtomicWritePath(path)
	if err != nil {
		return err
	}
	target, err = canonicalAtomicTransformTargetPath(target)
	if err != nil {
		return err
	}
	if err := validateAtomicTransformBoundLeaf(filepath.Base(target)); err != nil {
		return fmt.Errorf("validate compare-and-swap target leaf: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return fmt.Errorf("create compare-and-swap target parent: %w", err)
	}
	return nil
}

func beginAtomicTransformV2(
	inputPath, path, stateDir string,
	snapshot atomicFileSnapshot,
	result atomicTransformResult,
	perm os.FileMode,
) (*atomicTransformV2Transaction, error) {
	target, err := canonicalAtomicTransformTargetPath(snapshot.writePath)
	if err != nil {
		return nil, err
	}
	if err := validateAtomicTransformBoundLeaf(filepath.Base(target)); err != nil {
		return nil, fmt.Errorf("validate compare-and-swap target leaf: %w", err)
	}
	targetDir, err := bindAtomicTransformDirectory(filepath.Dir(target))
	if err != nil {
		return nil, fmt.Errorf("bind compare-and-swap target parent: %w", err)
	}
	stateBound, err := bindAtomicTransformDirectory(stateDir)
	if err != nil {
		_ = targetDir.Close()
		return nil, fmt.Errorf("bind stable compare-and-swap state directory: %w", err)
	}
	txn := &atomicTransformV2Transaction{targetDir: targetDir, stateDir: stateBound}
	failClosed := func(cause error) (*atomicTransformV2Transaction, error) {
		return nil, errors.Join(cause, txn.close())
	}
	if snapshot.parentIdentity == "" || targetDir.identity != snapshot.parentIdentity {
		return failClosed(errAtomicTransformConflict)
	}
	if err := atomicTransformValidateStableVolumeLocatorPlatform(path, targetDir); err != nil {
		return failClosed(err)
	}
	if err := stateBound.validatePrivate(); err != nil {
		return failClosed(err)
	}
	if !atomicTransformPathsEqual(stateDir, stateBound.path) {
		return failClosed(fmt.Errorf("stable compare-and-swap state locator is an alias; use its canonical non-reparse path"))
	}
	if err := atomicTransformValidateNoReparsePathPlatform(path); err != nil {
		return failClosed(fmt.Errorf("revalidate Windows config locator after binding: %w", err))
	}
	if err := atomicTransformValidateNoReparsePathPlatform(stateDir); err != nil {
		return failClosed(fmt.Errorf("revalidate Windows transaction locator after binding: %w", err))
	}
	logical, base, err := atomicTransformV2BasePath(path, stateBound.path)
	if err != nil {
		return failClosed(err)
	}
	txn.base = base
	normalizedInput, err := canonicalAtomicTransformPath(inputPath)
	if err != nil {
		return failClosed(err)
	}
	txnID, err := atomicTransformV2RandomHex(24)
	if err != nil {
		return failClosed(err)
	}
	receipt := atomicTransformV2Receipt{
		Version: atomicTransformV2Version, Phase: atomicTransformV2Allocation,
		TransactionID: txnID, LogicalPath: logical, InputPath: normalizedInput,
		StateDir: stateBound.path, StateDirIdentity: stateBound.identity,
		TargetPath: target, TargetParentIdentity: targetDir.identity,
		OldExists: snapshot.exists, Remove: result.Remove,
		RequestedPrivate: perm.Perm()&0o077 == 0,
	}
	if snapshot.exists {
		oldState, inspectErr := atomicTransformBoundInspect(targetDir, filepath.Base(target), atomicTransformMaxConfigBytes)
		if inspectErr != nil || !oldState.exists || !atomicTransformSnapshotMatchesState(snapshot, oldState) {
			if inspectErr == nil {
				inspectErr = errAtomicTransformConflict
			}
			return failClosed(inspectErr)
		}
		receipt.Old = atomicTransformV2ArtifactFromState(filepath.Base(target), oldState)
		receipt.TargetShortName, err = atomicTransformV2CaptureWindowsShortName(
			targetDir, filepath.Base(target), oldState,
		)
		if err != nil {
			return failClosed(fmt.Errorf("capture exact prior-config Windows short name: %w", err))
		}
		receipt.TombstoneName, err = atomicTransformV2RandomBoundName(targetDir, "old")
		if err != nil {
			return failClosed(err)
		}
		receipt.TerminalMarkerName = receipt.TombstoneName
	} else {
		receipt.TerminalMarkerName, err = atomicTransformV2RandomBoundName(targetDir, "committed")
		if err != nil {
			return failClosed(err)
		}
	}
	planName := func(label string) (string, error) {
		return atomicTransformV2RandomBoundName(targetDir, label)
	}
	receipt.TerminalMarker.Name, err = planName("marker-terminal")
	if err != nil {
		return failClosed(err)
	}
	if !result.Remove {
		receipt.Stage.Name, err = planName("stage")
		if err != nil {
			return failClosed(err)
		}
		receipt.StageFinalName, err = planName("ready")
		if err != nil {
			return failClosed(err)
		}
		receipt.StageMarker.Name, err = planName("marker-stage")
		if err != nil {
			return failClosed(err)
		}
		receipt.FinalMarker.Name, err = planName("marker-ready")
		if err != nil {
			return failClosed(err)
		}
	}
	allocationState, err := persistAtomicTransformV2AllocationReceipt(stateBound, base, receipt)
	if err != nil {
		return failClosed(err)
	}
	txn.allocationState = allocationState
	if err := runAtomicTransformPhaseHook(
		path, atomicTransformPhaseAllocationPersisted, atomicTransformV2HookState(base, receipt),
	); err != nil {
		return failClosed(err)
	}

	publishMarker := func(
		name, label string, bootstrapPhase atomicTransformPhase,
	) (atomicTransformArtifactState, error) {
		tempName, nameErr := atomicTransformV2RandomBoundName(targetDir, "bootstrap-"+label)
		if nameErr != nil {
			return atomicTransformArtifactState{}, nameErr
		}
		state, publishErr := atomicTransformBoundPublishBootstrap(
			targetDir, tempName, name, atomicTransformV2MarkerBytes(txnID, label),
			0o600, false,
			func(_ string) error {
				return runAtomicTransformPhaseHook(
					path, bootstrapPhase, atomicTransformV2HookState(base, receipt),
				)
			},
		)
		if publishErr != nil {
			return atomicTransformArtifactState{}, publishErr
		}
		if hookErr := runAtomicTransformPhaseHook(
			path, atomicTransformPhasePreReceiptArtifact, atomicTransformV2HookState(base, receipt),
		); hookErr != nil {
			return atomicTransformArtifactState{}, hookErr
		}
		return state, nil
	}
	terminal, err := publishMarker(
		receipt.TerminalMarker.Name, "terminal", atomicTransformPhaseTerminalMarkerBootstrap,
	)
	if err != nil {
		return failClosed(err)
	}
	receipt.TerminalMarker = atomicTransformV2ArtifactFromState(receipt.TerminalMarker.Name, terminal)
	var stageInitial atomicTransformArtifactState
	if !result.Remove {
		stageInitial, err = publishMarker(
			receipt.Stage.Name, "payload", atomicTransformPhasePayloadMarkerBootstrap,
		)
		if err != nil {
			return failClosed(err)
		}
		receipt.Stage = atomicTransformV2ArtifactFromState(receipt.Stage.Name, stageInitial)
		receipt.Stage.SHA256 = atomicTransformDigest(result.Data)
		receipt.Stage.Size = int64(len(result.Data))
		// Rs authenticates the preallocated inode/protection and expected main
		// bytes, but final metadata (notably LastWriteTime and the main BackupRead
		// stream) does not exist until the held file is fully written and closed.
		// Rp records the complete final metadata witness below.
		receipt.Stage.MetadataSHA256 = ""
		receipt.Stage.StageOwnedMetadataSHA256 = ""
		receipt.Stage.CreationTime = 0
		receipt.Stage.LastWriteTime = 0
		stageMarker, createErr := publishMarker(
			receipt.StageMarker.Name, "stage", atomicTransformPhaseStageMarkerBootstrap,
		)
		if createErr != nil {
			return failClosed(createErr)
		}
		receipt.StageMarker = atomicTransformV2ArtifactFromState(receipt.StageMarker.Name, stageMarker)
		finalMarker, createErr := publishMarker(
			receipt.FinalMarker.Name, "ready", atomicTransformPhaseReadyMarkerBootstrap,
		)
		if createErr != nil {
			return failClosed(createErr)
		}
		receipt.FinalMarker = atomicTransformV2ArtifactFromState(receipt.FinalMarker.Name, finalMarker)
	}

	receipt.Phase = atomicTransformV2Staging
	stagingState, err := persistAtomicTransformV2StagingReceiptArmed(stateBound, base, receipt)
	if err != nil {
		return failClosed(err)
	}
	txn.receipt, txn.stagingState = receipt, stagingState
	if err := runAtomicTransformPhaseHook(
		path, atomicTransformPhaseStagingLocated, atomicTransformV2HookState(base, receipt),
	); err != nil {
		return txn, err
	}
	if result.Remove {
		receipt.StagingReceiptID = stagingState.identity
		preparedState, persistErr := persistAtomicTransformV2Receipt(stateBound, base, receipt, atomicTransformV2Prepared)
		if persistErr != nil {
			return txn, persistErr
		}
		receipt.Phase = atomicTransformV2Prepared
		txn.receipt, txn.preparedState = receipt, preparedState
		if hookErr := runAtomicTransformPhaseHook(
			path, atomicTransformPhaseIntentPersisted, atomicTransformV2HookState(base, receipt),
		); hookErr != nil {
			return txn, hookErr
		}
		return txn, nil
	}

	stageFile, err := openAtomicTransformBoundFilePlatform(targetDir.file, receipt.Stage.Name, true)
	if err != nil {
		return txn, err
	}
	stageOpen := true
	closeStage := func() error {
		if !stageOpen {
			return nil
		}
		stageOpen = false
		return stageFile.Close()
	}
	currentStage, err := atomicTransformBoundStateFromOpen(
		stageFile, receipt.Stage.Name, atomicTransformMaxConfigBytes,
	)
	if err != nil || !atomicTransformArtifactStatesEqualExact(currentStage, stageInitial) {
		if err == nil {
			err = fmt.Errorf("allocation-authenticated payload marker changed before Rs")
		}
		return txn, errors.Join(err, closeStage())
	}
	if err := stageFile.Truncate(0); err != nil {
		return txn, errors.Join(err, closeStage())
	}
	if _, err := stageFile.Seek(0, 0); err != nil {
		return txn, errors.Join(err, closeStage())
	}
	if err := stageFile.Sync(); err != nil {
		return txn, errors.Join(err, closeStage())
	}
	prefix := len(result.Data) / 2
	if prefix == 0 && len(result.Data) != 0 {
		prefix = 1
	}
	if written, writeErr := stageFile.Write(result.Data[:prefix]); writeErr != nil {
		return txn, errors.Join(writeErr, closeStage())
	} else if written != prefix {
		return txn, errors.Join(io.ErrShortWrite, closeStage())
	}
	if hookErr := runAtomicTransformPhaseHook(
		path, atomicTransformPhaseStagePartial, atomicTransformV2HookState(base, receipt),
	); hookErr != nil {
		return txn, errors.Join(hookErr, closeStage())
	}
	if written, writeErr := stageFile.Write(result.Data[prefix:]); writeErr != nil {
		return txn, errors.Join(writeErr, closeStage())
	} else if written != len(result.Data)-prefix {
		return txn, errors.Join(io.ErrShortWrite, closeStage())
	}
	if err := stageFile.Sync(); err != nil {
		return txn, errors.Join(err, closeStage())
	}
	if err := closeStage(); err != nil {
		return txn, err
	}
	written, err := atomicTransformBoundInspectFilePrivate(targetDir, receipt.Stage.Name, atomicTransformMaxConfigBytes)
	if err != nil || !atomicTransformV2StateMatches(receipt.Stage, written, true) {
		if err == nil {
			err = fmt.Errorf("tracked compare-and-swap stage changed before durable namespace publication")
		}
		return txn, err
	}
	receipt.Stage = atomicTransformV2ArtifactFromState(receipt.Stage.Name, written)
	ready, err := atomicTransformBoundRenameNoReplace(
		targetDir, receipt.Stage.Name, receipt.StageFinalName, written,
	)
	if err != nil {
		return txn, err
	}
	// NTFS may normalize CreationTime while the exact held rename handle denies
	// content and metadata writers. Persist Rp from the post-rename exact state,
	// never from the pre-rename provisional witness.
	receipt.Stage = atomicTransformV2ArtifactFromState(receipt.Stage.Name, ready)
	// The stage-finalized seam remains before Rp. Windows tests use it to assign
	// a deterministic DOS alias through an exact StageFinal handle; production
	// installs no hook. Capture the complete post-hook state so Rp authenticates
	// the alias owner and every metadata witness actually being published.
	if hookErr := runAtomicTransformPhaseHook(
		path, atomicTransformPhaseStageFinalized, atomicTransformV2HookState(base, receipt),
	); hookErr != nil {
		return txn, hookErr
	}
	ready, err = atomicTransformBoundInspectFilePrivate(
		targetDir, receipt.StageFinalName, atomicTransformMaxConfigBytes,
	)
	if err != nil || ready.identity != receipt.Stage.Identity ||
		ready.digest != receipt.Stage.SHA256 || ready.size != receipt.Stage.Size || ready.linkCount != 1 {
		if err == nil {
			err = fmt.Errorf("ready Stage changed at the pre-Rp finalization seam")
		}
		return txn, err
	}
	receipt.Stage = atomicTransformV2ArtifactFromState(receipt.Stage.Name, ready)
	receipt.StageShortName, err = atomicTransformV2CaptureWindowsShortName(
		targetDir, receipt.StageFinalName, ready,
	)
	if err != nil {
		return txn, fmt.Errorf("capture exact ready-stage Windows short name: %w", err)
	}
	receipt.StagingReceiptID = stagingState.identity
	preparedState, err := persistAtomicTransformV2Receipt(stateBound, base, receipt, atomicTransformV2Prepared)
	if err != nil {
		return txn, err
	}
	receipt.Phase = atomicTransformV2Prepared
	txn.receipt, txn.preparedState = receipt, preparedState
	if hookErr := runAtomicTransformPhaseHook(
		path, atomicTransformPhaseIntentPersisted, atomicTransformV2HookState(base, receipt),
	); hookErr != nil {
		return txn, hookErr
	}
	return txn, nil
}

func persistAtomicTransformV2AllocationReceipt(
	stateDir *atomicTransformBoundDirectory, base string, receipt atomicTransformV2Receipt,
) (atomicTransformArtifactState, error) {
	return persistAtomicTransformV2Receipt(stateDir, base, receipt, atomicTransformV2Allocation)
}

func persistAtomicTransformV2StagingReceiptArmed(
	stateDir *atomicTransformBoundDirectory, base string, receipt atomicTransformV2Receipt,
) (atomicTransformArtifactState, error) {
	state, err := persistAtomicTransformV2Receipt(stateDir, base, receipt, atomicTransformV2Staging)
	if err != nil {
		return atomicTransformArtifactState{}, err
	}
	if err := runAtomicTransformPhaseHook(
		receipt.LogicalPath, atomicTransformPhasePreReceiptArtifact,
		atomicTransformV2HookState(base, receipt),
	); err != nil {
		return atomicTransformArtifactState{}, err
	}
	return state, nil
}

func atomicTransformSnapshotMatchesState(snapshot atomicFileSnapshot, state atomicTransformArtifactState) bool {
	return state.exists && snapshot.exists && os.SameFile(snapshot.info, state.info) &&
		state.identity == snapshot.identity &&
		state.digest == atomicTransformDigest(snapshot.data) && state.size == int64(len(snapshot.data)) &&
		state.info.Mode() == snapshot.info.Mode() && state.protectionDigest == snapshot.protectionDigest &&
		state.metadataDigest == snapshot.metadataDigest &&
		state.preservedMetadataDigest == snapshot.preservedMetadataDigest &&
		state.stageOwnedMetadataDigest == snapshot.stageOwnedMetadataDigest &&
		state.ownerGroupDigest == snapshot.ownerGroupDigest &&
		state.creationTime == snapshot.creationTime && state.lastWriteTime == snapshot.lastWriteTime &&
		state.linkCount == snapshot.linkCount
}

func atomicTransformV2ArtifactFromState(name string, state atomicTransformArtifactState) atomicTransformV2Artifact {
	return atomicTransformV2Artifact{
		Name: name, Identity: state.identity, SHA256: state.digest, Size: state.size,
		Mode: uint32(state.info.Mode()), ProtectionSHA256: state.protectionDigest,
		MetadataSHA256: state.metadataDigest, PreservedMetadataSHA256: state.preservedMetadataDigest,
		StageOwnedMetadataSHA256: state.stageOwnedMetadataDigest,
		OwnerGroupSHA256:         state.ownerGroupDigest,
		CreationTime:             state.creationTime, LastWriteTime: state.lastWriteTime,
		LinkCount: state.linkCount,
	}
}

func atomicTransformV2StateMatches(record atomicTransformV2Artifact, state atomicTransformArtifactState, contents bool) bool {
	if !state.exists || record.Identity == "" || state.identity != record.Identity ||
		state.info.Mode() != os.FileMode(record.Mode) || state.protectionDigest != record.ProtectionSHA256 ||
		(record.MetadataSHA256 != "" && state.metadataDigest != record.MetadataSHA256) ||
		(record.PreservedMetadataSHA256 != "" &&
			state.preservedMetadataDigest != record.PreservedMetadataSHA256) ||
		(record.StageOwnedMetadataSHA256 != "" &&
			state.stageOwnedMetadataDigest != record.StageOwnedMetadataSHA256) ||
		(record.OwnerGroupSHA256 != "" && state.ownerGroupDigest != record.OwnerGroupSHA256) ||
		(record.CreationTime != 0 && state.creationTime != record.CreationTime) ||
		(record.LastWriteTime != 0 && state.lastWriteTime != record.LastWriteTime) {
		return false
	}
	if record.LinkCount != 0 && state.linkCount != record.LinkCount {
		return false
	}
	return !contents || (state.digest == record.SHA256 && state.size == record.Size)
}

// NTFS may normalize CreationTime and ARCHIVE/NORMAL during a held rename.
// This is the complete post-rename witness: everything else remains bound to
// the recorded inode and must match exactly.
func atomicTransformV2RenamedArtifactMatches(
	record atomicTransformV2Artifact, state atomicTransformArtifactState,
) bool {
	return state.exists && record.Identity != "" && state.identity == record.Identity &&
		state.digest == record.SHA256 && state.size == record.Size &&
		state.info.Mode() == os.FileMode(record.Mode) &&
		state.protectionDigest == record.ProtectionSHA256 &&
		record.PreservedMetadataSHA256 != "" &&
		state.preservedMetadataDigest == record.PreservedMetadataSHA256 &&
		record.StageOwnedMetadataSHA256 != "" &&
		state.stageOwnedMetadataDigest == record.StageOwnedMetadataSHA256 &&
		record.OwnerGroupSHA256 != "" && state.ownerGroupDigest == record.OwnerGroupSHA256 &&
		record.LastWriteTime != 0 && state.lastWriteTime == record.LastWriteTime &&
		record.LinkCount == 1 && state.linkCount == 1
}

func atomicTransformV2PublishedTargetMatches(
	receipt atomicTransformV2Receipt, state atomicTransformArtifactState,
) bool {
	if !receipt.OldExists {
		return atomicTransformV2RenamedArtifactMatches(receipt.Stage, state)
	}
	return atomicTransformV2StageContentMatches(receipt.Stage, state) &&
		receipt.Stage.LinkCount == 1 && state.linkCount == 1 &&
		receipt.Old.PreservedMetadataSHA256 != "" &&
		state.preservedMetadataDigest == receipt.Old.PreservedMetadataSHA256 &&
		receipt.Stage.OwnerGroupSHA256 != "" &&
		state.ownerGroupDigest == receipt.Stage.OwnerGroupSHA256 &&
		receipt.Old.CreationTime != 0 && state.creationTime == receipt.Old.CreationTime
}

func atomicTransformV2KnownStageState(
	receipt atomicTransformV2Receipt, state atomicTransformArtifactState,
) bool {
	return (receipt.Stage.MetadataSHA256 != "" &&
		receipt.Stage.StageOwnedMetadataSHA256 != "" &&
		atomicTransformV2StateMatches(receipt.Stage, state, true)) ||
		atomicTransformV2PublishedTargetMatches(receipt, state)
}

func atomicTransformV2KnownOldState(
	record atomicTransformV2Artifact, state atomicTransformArtifactState,
) bool {
	return atomicTransformV2StateMatches(record, state, true) ||
		atomicTransformV2RenamedArtifactMatches(record, state) ||
		atomicTransformV2BackupOldMatches(record, state)
}

func atomicTransformV2RandomHex(bytesCount int) (string, error) {
	value := make([]byte, bytesCount)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate compare-and-swap transaction identifier: %w", err)
	}
	return hex.EncodeToString(value), nil
}

func atomicTransformV2RandomBoundName(dir *atomicTransformBoundDirectory, label string) (string, error) {
	for attempt := 0; attempt < atomicTransformMaxAttempts; attempt++ {
		random, err := atomicTransformV2RandomHex(16)
		if err != nil {
			return "", err
		}
		name := atomicTransformV2NamePrefix + label + "-" + random
		state, err := atomicTransformBoundInspect(dir, name, atomicTransformMaxConfigBytes)
		if err != nil {
			return "", err
		}
		if !state.exists {
			return name, nil
		}
	}
	return "", fmt.Errorf("could not reserve unique bound compare-and-swap %s name", label)
}

func createAtomicTransformV2Marker(
	dir *atomicTransformBoundDirectory, txnID, label string,
) (atomicTransformV2Artifact, error) {
	content := atomicTransformV2MarkerBytes(txnID, label)
	name, err := atomicTransformV2RandomBoundName(dir, "marker-"+label)
	if err != nil {
		return atomicTransformV2Artifact{}, err
	}
	state, err := atomicTransformBoundCreate(dir, name, content, 0o600)
	if err != nil {
		return atomicTransformV2Artifact{}, fmt.Errorf("create durable harmless %s marker: %w", label, err)
	}
	privateState, err := atomicTransformBoundInspectFilePrivate(dir, name, atomicTransformMaxIntentBytes)
	if err != nil || !atomicTransformArtifactStatesEqualExact(privateState, state) {
		if err == nil {
			err = fmt.Errorf("created harmless %s marker changed before privacy validation", label)
		}
		_ = atomicTransformBoundDeleteExact(dir, name, state)
		return atomicTransformV2Artifact{}, err
	}
	return atomicTransformV2ArtifactFromState(name, state), nil
}

func atomicTransformV2MarkerBytes(txnID, label string) []byte {
	return []byte(fmt.Sprintf("%s\n%s\n%s\n", atomicTransformV2MarkerVersion, txnID, label))
}

func atomicTransformV2ReceiptPath(base, phase string) string {
	switch phase {
	case atomicTransformV2Allocation:
		return base + ".allocation"
	case atomicTransformV2Staging:
		return base
	case atomicTransformV2Prepared:
		return base + ".prepared"
	case atomicTransformV2Terminal:
		return base + ".terminal"
	case atomicTransformV2Complete:
		return base + ".complete"
	default:
		return ""
	}
}

func atomicTransformV2BasePath(path, stateDir string) (string, string, error) {
	logical, err := canonicalAtomicTransformPath(path)
	if err != nil {
		return "", "", err
	}
	stateDir, err = canonicalAtomicTransformPath(stateDir)
	if err != nil {
		return "", "", err
	}
	digest := atomicTransformDigest([]byte(logical))[:24]
	return logical, filepath.Join(stateDir, atomicTransformV2ReceiptPrefix+digest+".intent"), nil
}

func marshalAtomicTransformV2Receipt(receipt atomicTransformV2Receipt, phase string) ([]byte, error) {
	receipt.Phase = phase
	body, err := json.Marshal(receipt)
	if err != nil {
		return nil, err
	}
	if len(body)+1 > atomicTransformMaxIntentBytes {
		return nil, fmt.Errorf("compare-and-swap receipt exceeds %d-byte limit", atomicTransformMaxIntentBytes)
	}
	return append(body, '\n'), nil
}

func persistAtomicTransformV2Receipt(
	stateDir *atomicTransformBoundDirectory,
	base string,
	receipt atomicTransformV2Receipt,
	phase string,
) (atomicTransformArtifactState, error) {
	if err := stateDir.validatePrivate(); err != nil {
		return atomicTransformArtifactState{}, fmt.Errorf("validate stable private state directory before receipt publication: %w", err)
	}
	path := atomicTransformV2ReceiptPath(base, phase)
	if path == "" {
		return atomicTransformArtifactState{}, fmt.Errorf("invalid compare-and-swap receipt phase %q", phase)
	}
	phaseReceipt := receipt
	phaseReceipt.Phase = phase
	body, err := marshalAtomicTransformV2Receipt(phaseReceipt, phase)
	if err != nil {
		return atomicTransformArtifactState{}, err
	}
	tmpName, err := atomicTransformV2RandomBoundName(stateDir, "bootstrap-"+phase)
	if err != nil {
		return atomicTransformArtifactState{}, err
	}
	finalName := filepath.Base(path)
	bootstrapPhase := map[string]atomicTransformPhase{
		atomicTransformV2Allocation: atomicTransformPhaseAllocationBootstrap,
		atomicTransformV2Staging:    atomicTransformPhaseStagingBootstrap,
		atomicTransformV2Prepared:   atomicTransformPhasePreparedBootstrap,
		atomicTransformV2Terminal:   atomicTransformPhaseTerminalBootstrap,
		atomicTransformV2Complete:   atomicTransformPhaseCompleteBootstrap,
	}[phase]
	return atomicTransformBoundPublishBootstrap(
		stateDir, tmpName, finalName, body, 0o600, true,
		func(_ string) error {
			return runAtomicTransformPhaseHook(
				phaseReceipt.LogicalPath, bootstrapPhase, atomicTransformV2HookState(base, phaseReceipt),
			)
		},
	)
}

func atomicTransformV2HookState(base string, receipt atomicTransformV2Receipt) atomicTransformPhaseState {
	receiptPath := atomicTransformV2ReceiptPath(base, receipt.Phase)
	if receiptPath == "" {
		receiptPath = base
	}
	activeStage := receipt.StageFinalName
	if receipt.Phase == atomicTransformV2Staging {
		activeStage = receipt.Stage.Name
	}
	state := atomicTransformPhaseState{
		IntentPath:        receiptPath,
		ReceiptPath:       receiptPath,
		TargetPath:        receipt.TargetPath,
		Tombstone:         filepath.Join(filepath.Dir(receipt.TargetPath), receipt.TombstoneName),
		Staged:            filepath.Join(filepath.Dir(receipt.TargetPath), activeStage),
		StagedProvisional: filepath.Join(filepath.Dir(receipt.TargetPath), receipt.Stage.Name),
		StagedFinal:       filepath.Join(filepath.Dir(receipt.TargetPath), receipt.StageFinalName),
		TerminalMarker:    filepath.Join(filepath.Dir(receipt.TargetPath), receipt.TerminalMarkerName),
	}
	if receipt.TombstoneName == "" {
		state.Tombstone = filepath.Join(filepath.Dir(receipt.TargetPath), receipt.TerminalMarkerName)
	}
	if activeStage == "" {
		state.Staged = ""
	}
	if receipt.Stage.Name == "" {
		state.StagedProvisional = ""
	}
	if receipt.StageFinalName == "" {
		state.StagedFinal = ""
	}
	return state
}

func decodeAtomicTransformV2Receipt(state atomicTransformArtifactState, path string) (atomicTransformV2Receipt, error) {
	decoder := json.NewDecoder(bytes.NewReader(state.data))
	decoder.DisallowUnknownFields()
	var receipt atomicTransformV2Receipt
	if err := decoder.Decode(&receipt); err != nil {
		return receipt, fmt.Errorf("parse compare-and-swap receipt %s: %w", path, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return receipt, fmt.Errorf("compare-and-swap receipt has trailing content: %s", path)
	}
	return receipt, nil
}

func atomicTransformV2ReceiptEquivalent(a, b atomicTransformV2Receipt) bool {
	allocationComparison := a.Phase == atomicTransformV2Allocation || b.Phase == atomicTransformV2Allocation
	a.Phase = atomicTransformV2Staging
	b.Phase = atomicTransformV2Staging
	a.StagingReceiptID, b.StagingReceiptID = "", ""
	a.PreparedReceiptID, b.PreparedReceiptID = "", ""
	a.TerminalReceiptID, b.TerminalReceiptID = "", ""
	a.Decision, b.Decision = "", ""
	if allocationComparison {
		namesOnly := func(artifact atomicTransformV2Artifact) atomicTransformV2Artifact {
			return atomicTransformV2Artifact{Name: artifact.Name}
		}
		a.Stage, b.Stage = namesOnly(a.Stage), namesOnly(b.Stage)
		a.StageMarker, b.StageMarker = namesOnly(a.StageMarker), namesOnly(b.StageMarker)
		a.FinalMarker, b.FinalMarker = namesOnly(a.FinalMarker), namesOnly(b.FinalMarker)
		a.TerminalMarker, b.TerminalMarker = namesOnly(a.TerminalMarker), namesOnly(b.TerminalMarker)
	}
	stageIncomplete := a.Stage.MetadataSHA256 == "" || b.Stage.MetadataSHA256 == ""
	if stageIncomplete {
		a.Stage.MetadataSHA256, b.Stage.MetadataSHA256 = "", ""
		a.Stage.StageOwnedMetadataSHA256, b.Stage.StageOwnedMetadataSHA256 = "", ""
		a.Stage.CreationTime, b.Stage.CreationTime = 0, 0
		a.Stage.LastWriteTime, b.Stage.LastWriteTime = 0, 0
		a.StageShortName, b.StageShortName = "", ""
	}
	aBytes, aErr := json.Marshal(a)
	bBytes, bErr := json.Marshal(b)
	return aErr == nil && bErr == nil && bytes.Equal(aBytes, bBytes)
}

func validateAtomicTransformV2Receipt(
	receipt atomicTransformV2Receipt, logical, stateDir, base, sourcePath string,
) error {
	if receipt.Version != atomicTransformV2Version {
		return fmt.Errorf("unsupported compare-and-swap receipt version %d", receipt.Version)
	}
	if receipt.Phase != atomicTransformV2Staging && receipt.Phase != atomicTransformV2Prepared &&
		receipt.Phase != atomicTransformV2Allocation && receipt.Phase != atomicTransformV2Terminal &&
		receipt.Phase != atomicTransformV2Complete {
		return fmt.Errorf("unsupported compare-and-swap receipt phase %q", receipt.Phase)
	}
	if len(receipt.TransactionID) != 48 {
		return fmt.Errorf("invalid compare-and-swap transaction identifier")
	}
	if _, err := hex.DecodeString(receipt.TransactionID); err != nil || receipt.TransactionID != strings.ToLower(receipt.TransactionID) {
		return fmt.Errorf("invalid compare-and-swap transaction identifier")
	}
	owner, err := canonicalAtomicTransformPath(receipt.LogicalPath)
	if err != nil || !filepath.IsAbs(receipt.LogicalPath) ||
		!atomicTransformPathsEqual(owner, receipt.LogicalPath) ||
		!atomicTransformLocationsEquivalent(owner, logical) {
		return fmt.Errorf("compare-and-swap receipt belongs to another logical path")
	}
	input, err := canonicalAtomicTransformPath(receipt.InputPath)
	if err != nil || !filepath.IsAbs(receipt.InputPath) ||
		!atomicTransformPathsEqual(input, receipt.InputPath) {
		return fmt.Errorf("compare-and-swap receipt input locator is not normalized and absolute")
	}
	storedState, err := canonicalAtomicTransformPath(receipt.StateDir)
	if err != nil || !filepath.IsAbs(receipt.StateDir) ||
		!atomicTransformPathsEqual(storedState, receipt.StateDir) ||
		!atomicTransformLocationsEquivalent(storedState, stateDir) {
		return fmt.Errorf("compare-and-swap receipt belongs to another stable state directory")
	}
	_, expectedBase, err := atomicTransformV2BasePath(owner, storedState)
	if err != nil || !atomicTransformPathsEqual(expectedBase, base) {
		return fmt.Errorf("compare-and-swap receipt path does not match its owner")
	}
	if receipt.StateDirIdentity == "" || receipt.TargetParentIdentity == "" {
		return fmt.Errorf("compare-and-swap receipt has no durable directory identity")
	}
	if receipt.TargetPath == "" || !filepath.IsAbs(receipt.TargetPath) {
		return fmt.Errorf("compare-and-swap receipt target is not absolute")
	}
	if err := validateAtomicTransformBoundLeaf(filepath.Base(receipt.TargetPath)); err != nil {
		return fmt.Errorf("compare-and-swap target leaf is unsafe: %w", err)
	}
	canonicalTarget, err := canonicalAtomicTransformTargetPath(receipt.TargetPath)
	if err != nil || !atomicTransformPathsEqual(canonicalTarget, receipt.TargetPath) {
		return fmt.Errorf("compare-and-swap receipt target is not canonical")
	}
	if receipt.OldExists && !atomicTransformPathsEqual(receipt.Old.Name, filepath.Base(receipt.TargetPath)) {
		return fmt.Errorf("compare-and-swap prior-config metadata does not name the live target")
	}
	if receipt.TargetShortName != "" {
		if !receipt.OldExists {
			return fmt.Errorf("compare-and-swap short-name witness has no prior config")
		}
		if err := validateAtomicTransformBoundLeaf(receipt.TargetShortName); err != nil {
			return fmt.Errorf("compare-and-swap target short name is unsafe: %w", err)
		}
		if atomicTransformPathsEqual(receipt.TargetShortName, filepath.Base(receipt.TargetPath)) {
			return fmt.Errorf("compare-and-swap target short name is not distinct")
		}
	}
	if receipt.StageShortName != "" {
		if receipt.Remove || receipt.Phase == atomicTransformV2Allocation ||
			receipt.Phase == atomicTransformV2Staging {
			return fmt.Errorf("compare-and-swap ready-stage short-name witness is premature")
		}
		if err := validateAtomicTransformBoundLeaf(receipt.StageShortName); err != nil {
			return fmt.Errorf("compare-and-swap ready-stage short name is unsafe: %w", err)
		}
		if atomicTransformPathsEqual(receipt.StageShortName, receipt.StageFinalName) ||
			(receipt.TargetShortName != "" &&
				atomicTransformPathsEqual(receipt.StageShortName, receipt.TargetShortName)) {
			return fmt.Errorf("compare-and-swap ready-stage short name overlaps another owned locator")
		}
	}
	switch receipt.Phase {
	case atomicTransformV2Allocation:
		if receipt.StagingReceiptID != "" || receipt.PreparedReceiptID != "" ||
			receipt.TerminalReceiptID != "" || receipt.Decision != "" {
			return fmt.Errorf("allocation receipt contains future-phase authorization")
		}
	case atomicTransformV2Staging:
		if receipt.StagingReceiptID != "" || receipt.PreparedReceiptID != "" ||
			receipt.TerminalReceiptID != "" || receipt.Decision != "" {
			return fmt.Errorf("staging receipt contains future-phase authorization")
		}
	case atomicTransformV2Prepared:
		if receipt.StagingReceiptID == "" || receipt.PreparedReceiptID != "" ||
			receipt.TerminalReceiptID != "" || receipt.Decision != "" {
			return fmt.Errorf("prepared receipt identity chain is invalid")
		}
	case atomicTransformV2Terminal:
		if receipt.StagingReceiptID == "" || receipt.PreparedReceiptID == "" ||
			receipt.TerminalReceiptID != "" ||
			(receipt.Decision != atomicTransformV2DecisionCommit && receipt.Decision != atomicTransformV2DecisionAbort) {
			return fmt.Errorf("terminal receipt identity chain is invalid")
		}
	case atomicTransformV2Complete:
		stagingOnlyAbort := receipt.StagingReceiptID != "" && receipt.PreparedReceiptID == "" &&
			receipt.TerminalReceiptID == "" && receipt.Decision == atomicTransformV2DecisionAbort
		fullTerminalChain := receipt.StagingReceiptID != "" && receipt.PreparedReceiptID != "" &&
			receipt.TerminalReceiptID != "" &&
			(receipt.Decision == atomicTransformV2DecisionCommit || receipt.Decision == atomicTransformV2DecisionAbort)
		if !stagingOnlyAbort && !fullTerminalChain {
			return fmt.Errorf("complete receipt identity/decision chain is invalid")
		}
	}
	validateName := func(label, name string, required bool) error {
		if name == "" && !required {
			return nil
		}
		if err := validateAtomicTransformBoundLeaf(name); err != nil {
			return fmt.Errorf("compare-and-swap %s name is invalid: %w", label, err)
		}
		if !strings.HasPrefix(name, atomicTransformV2NamePrefix) {
			return fmt.Errorf("compare-and-swap %s name is invalid", label)
		}
		return nil
	}
	for _, item := range []struct {
		label    string
		name     string
		required bool
	}{
		{"terminal marker", receipt.TerminalMarkerName, true},
		{"terminal marker source", receipt.TerminalMarker.Name, true},
		{"tombstone", receipt.TombstoneName, receipt.OldExists},
		{"stage", receipt.Stage.Name, !receipt.Remove},
		{"final stage", receipt.StageFinalName, !receipt.Remove},
		{"stage marker source", receipt.StageMarker.Name, !receipt.Remove},
		{"final marker source", receipt.FinalMarker.Name, !receipt.Remove},
	} {
		if err := validateName(item.label, item.name, item.required); err != nil {
			return fmt.Errorf("%s: %w", sourcePath, err)
		}
	}
	if receipt.Remove && (receipt.Stage != (atomicTransformV2Artifact{}) ||
		receipt.StageFinalName != "" || receipt.StageShortName != "" ||
		receipt.StageMarker != (atomicTransformV2Artifact{}) ||
		receipt.FinalMarker != (atomicTransformV2Artifact{})) {
		return fmt.Errorf("remove receipt unexpectedly contains staged replacement metadata")
	}
	if !receipt.OldExists && receipt.TombstoneName != "" {
		return fmt.Errorf("create receipt unexpectedly contains a prior-config tombstone")
	}
	if !receipt.OldExists && receipt.Old != (atomicTransformV2Artifact{}) {
		return fmt.Errorf("create receipt unexpectedly contains prior-config metadata")
	}
	if receipt.OldExists && receipt.TerminalMarkerName != receipt.TombstoneName {
		return fmt.Errorf("existing-target terminal marker is not bound to its tombstone slot")
	}
	for _, artifact := range []atomicTransformV2Artifact{
		receipt.TerminalMarker, receipt.StageMarker, receipt.FinalMarker,
	} {
		if artifact.Name == "" {
			continue
		}
		if receipt.Phase == atomicTransformV2Allocation {
			if artifact.Identity != "" || artifact.SHA256 != "" || artifact.Size != 0 ||
				artifact.Mode != 0 || artifact.ProtectionSHA256 != "" ||
				artifact.MetadataSHA256 != "" || artifact.PreservedMetadataSHA256 != "" ||
				artifact.StageOwnedMetadataSHA256 != "" || artifact.CreationTime != 0 ||
				artifact.OwnerGroupSHA256 != "" || artifact.LastWriteTime != 0 ||
				artifact.LinkCount != 0 {
				return fmt.Errorf("allocation receipt contains prematurely trusted marker metadata")
			}
			continue
		}
		if artifact.Identity == "" || artifact.Size < 0 || artifact.Size > atomicTransformMaxIntentBytes ||
			!atomicTransformV2ValidDigest(artifact.SHA256) {
			return fmt.Errorf("compare-and-swap marker metadata is invalid")
		}
	}
	for _, marker := range []struct {
		label    string
		artifact atomicTransformV2Artifact
	}{
		{"terminal", receipt.TerminalMarker},
		{"stage", receipt.StageMarker},
		{"ready", receipt.FinalMarker},
	} {
		if marker.artifact.Name == "" {
			continue
		}
		if receipt.Phase == atomicTransformV2Allocation {
			continue
		}
		expected := atomicTransformV2MarkerBytes(receipt.TransactionID, marker.label)
		if marker.artifact.SHA256 != atomicTransformDigest(expected) ||
			marker.artifact.Size != int64(len(expected)) ||
			os.FileMode(marker.artifact.Mode)&os.ModeType != 0 ||
			(runtime.GOOS != "windows" && os.FileMode(marker.artifact.Mode).Perm() != 0o600) ||
			(runtime.GOOS == "windows" && (!atomicTransformV2ValidDigest(marker.artifact.ProtectionSHA256) ||
				!atomicTransformV2ValidDigest(marker.artifact.MetadataSHA256) ||
				!atomicTransformV2ValidDigest(marker.artifact.PreservedMetadataSHA256) ||
				!atomicTransformV2ValidDigest(marker.artifact.StageOwnedMetadataSHA256) ||
				!atomicTransformV2ValidDigest(marker.artifact.OwnerGroupSHA256) ||
				marker.artifact.CreationTime == 0 || marker.artifact.LastWriteTime == 0 ||
				marker.artifact.LinkCount != 1)) {
			return fmt.Errorf("compare-and-swap %s marker is not self-authenticating private harmless content", marker.label)
		}
	}
	names := []string{
		receipt.Stage.Name, receipt.StageFinalName, receipt.StageMarker.Name,
		receipt.FinalMarker.Name, receipt.TerminalMarkerName,
		receipt.TerminalMarker.Name,
	}
	liveName := filepath.Base(receipt.TargetPath)
	for left := range names {
		if names[left] == "" {
			continue
		}
		if atomicTransformPathsEqual(names[left], liveName) {
			return fmt.Errorf("compare-and-swap artifact slot overlaps the live target")
		}
		for right := left + 1; right < len(names); right++ {
			if names[right] != "" && atomicTransformPathsEqual(names[left], names[right]) {
				return fmt.Errorf("compare-and-swap artifact names overlap")
			}
		}
	}
	identities := []string{
		receipt.Old.Identity, receipt.Stage.Identity, receipt.StageMarker.Identity,
		receipt.FinalMarker.Identity, receipt.TerminalMarker.Identity,
	}
	for left := range identities {
		if identities[left] == "" {
			continue
		}
		for right := left + 1; right < len(identities); right++ {
			if identities[left] == identities[right] {
				return fmt.Errorf("compare-and-swap artifact identities overlap")
			}
		}
	}
	if receipt.Phase == atomicTransformV2Allocation {
		if receipt.Stage.Identity != "" || receipt.Stage.SHA256 != "" || receipt.Stage.Size != 0 ||
			receipt.Stage.Mode != 0 || receipt.Stage.ProtectionSHA256 != "" ||
			receipt.Stage.MetadataSHA256 != "" || receipt.Stage.PreservedMetadataSHA256 != "" ||
			receipt.Stage.StageOwnedMetadataSHA256 != "" || receipt.Stage.CreationTime != 0 ||
			receipt.Stage.OwnerGroupSHA256 != "" || receipt.Stage.LastWriteTime != 0 ||
			receipt.Stage.LinkCount != 0 ||
			receipt.StageShortName != "" {
			return fmt.Errorf("allocation receipt contains prematurely trusted stage metadata")
		}
	}
	stageMetadataMustBeComplete := receipt.Phase == atomicTransformV2Prepared ||
		receipt.Phase == atomicTransformV2Terminal ||
		(receipt.Phase == atomicTransformV2Complete && receipt.PreparedReceiptID != "")
	stageMetadataMustBeIncomplete := receipt.Phase == atomicTransformV2Staging ||
		(receipt.Phase == atomicTransformV2Complete && receipt.PreparedReceiptID == "")
	if receipt.Phase != atomicTransformV2Allocation && !receipt.Remove && (receipt.Stage.Identity == "" || receipt.Stage.Size < 0 ||
		receipt.Stage.Size > atomicTransformMaxConfigBytes || !atomicTransformV2ValidDigest(receipt.Stage.SHA256) ||
		os.FileMode(receipt.Stage.Mode)&os.ModeType != 0 ||
		!atomicTransformV2ValidDigest(receipt.Stage.ProtectionSHA256) ||
		!atomicTransformV2ValidDigest(receipt.Stage.OwnerGroupSHA256) ||
		(runtime.GOOS == "windows" && (!atomicTransformV2ValidDigest(receipt.Stage.PreservedMetadataSHA256) ||
			receipt.Stage.LinkCount != 1 ||
			(stageMetadataMustBeComplete &&
				(!atomicTransformV2ValidDigest(receipt.Stage.MetadataSHA256) ||
					!atomicTransformV2ValidDigest(receipt.Stage.StageOwnedMetadataSHA256) ||
					receipt.Stage.CreationTime == 0 || receipt.Stage.LastWriteTime == 0))))) {
		return fmt.Errorf(
			"compare-and-swap stage metadata is invalid (phase=%s identity=%t size=%d sha=%d preserved=%d full=%d stage_owned=%d creation=%d last_write=%d links=%d)",
			receipt.Phase, receipt.Stage.Identity != "", receipt.Stage.Size,
			len(receipt.Stage.SHA256), len(receipt.Stage.PreservedMetadataSHA256),
			len(receipt.Stage.MetadataSHA256), len(receipt.Stage.StageOwnedMetadataSHA256),
			receipt.Stage.CreationTime, receipt.Stage.LastWriteTime, receipt.Stage.LinkCount,
		)
	}
	if !receipt.Remove && stageMetadataMustBeIncomplete &&
		(receipt.Stage.MetadataSHA256 != "" || receipt.Stage.StageOwnedMetadataSHA256 != "" ||
			receipt.Stage.CreationTime != 0 || receipt.Stage.LastWriteTime != 0 ||
			receipt.StageShortName != "") {
		return fmt.Errorf("incomplete-stage receipt contains premature final metadata")
	}
	if receipt.OldExists && (receipt.Old.Identity == "" || receipt.Old.Size < 0 ||
		receipt.Old.Size > atomicTransformMaxConfigBytes || !atomicTransformV2ValidDigest(receipt.Old.SHA256) ||
		os.FileMode(receipt.Old.Mode)&os.ModeType != 0 ||
		!atomicTransformV2ValidDigest(receipt.Old.ProtectionSHA256) ||
		!atomicTransformV2ValidDigest(receipt.Old.OwnerGroupSHA256) ||
		(runtime.GOOS == "windows" && (!atomicTransformV2ValidDigest(receipt.Old.MetadataSHA256) ||
			!atomicTransformV2ValidDigest(receipt.Old.PreservedMetadataSHA256) ||
			!atomicTransformV2ValidDigest(receipt.Old.StageOwnedMetadataSHA256) ||
			receipt.Old.CreationTime == 0 || receipt.Old.LastWriteTime == 0 ||
			receipt.Old.LinkCount != 1))) {
		return fmt.Errorf("compare-and-swap prior-config metadata is invalid")
	}
	return nil
}

const sha256HexLength = 64

func atomicTransformV2ValidDigest(value string) bool {
	if len(value) != sha256HexLength || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

type atomicTransformV2CandidateName struct {
	base, phase, transactionID string
	gc                         bool
}

func parseAtomicTransformV2Candidate(name string) (atomicTransformV2CandidateName, bool, error) {
	hasPrefix := strings.HasPrefix
	hasSuffix := strings.HasSuffix
	if runtime.GOOS == "windows" {
		hasPrefix = atomicTransformASCIIHasPrefix
		hasSuffix = atomicTransformASCIIHasSuffix
	}
	if !hasPrefix(name, atomicTransformV2ReceiptPrefix) {
		return atomicTransformV2CandidateName{}, false, nil
	}
	result := atomicTransformV2CandidateName{base: name, phase: atomicTransformV2Staging}
	const gcPrefix = ".gc-"
	if len(result.base) >= len(gcPrefix)+48 {
		gcStart := len(result.base) - len(gcPrefix) - 48
		if atomicTransformASCIIEqualFold(result.base[gcStart:gcStart+len(gcPrefix)], gcPrefix) {
			result.transactionID = result.base[gcStart+len(gcPrefix):]
			if len(result.transactionID) != 48 || result.transactionID != strings.ToLower(result.transactionID) {
				return result, true, fmt.Errorf("malformed reserved V2 CAS GC transaction identifier: %s", name)
			}
			if _, err := hex.DecodeString(result.transactionID); err != nil {
				return result, true, fmt.Errorf("malformed reserved V2 CAS GC transaction identifier: %s", name)
			}
			result.base = result.base[:gcStart]
			result.gc = true
		}
	}
	suffixes := []struct{ suffix, phase string }{
		{".allocation", atomicTransformV2Allocation},
		{".prepared", atomicTransformV2Prepared},
		{".terminal", atomicTransformV2Terminal},
		{".complete", atomicTransformV2Complete},
	}
	for _, suffix := range suffixes {
		if hasSuffix(result.base, suffix.suffix) {
			result.base = result.base[:len(result.base)-len(suffix.suffix)]
			result.phase = suffix.phase
			break
		}
	}
	for _, suffix := range suffixes {
		if hasSuffix(result.base, suffix.suffix) {
			return result, true, fmt.Errorf("stacked reserved V2 CAS receipt phase suffix: %s", name)
		}
	}
	if !hasSuffix(result.base, ".intent") {
		return result, true, fmt.Errorf("malformed reserved V2 CAS receipt name: %s", name)
	}
	digest := result.base[len(atomicTransformV2ReceiptPrefix) : len(result.base)-len(".intent")]
	if len(digest) != 24 {
		return result, true, fmt.Errorf("malformed reserved V2 CAS owner digest: %s", name)
	}
	for _, char := range digest {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') ||
			(runtime.GOOS == "windows" && char >= 'A' && char <= 'F')) {
			return result, true, fmt.Errorf("malformed reserved V2 CAS owner digest: %s", name)
		}
	}
	return result, true, nil
}

func atomicTransformV2Candidate(name string) (base, phase string, ok bool) {
	candidate, reserved, err := parseAtomicTransformV2Candidate(name)
	return candidate.base, candidate.phase, reserved && err == nil && !candidate.gc
}

type atomicTransformV2CandidateGroup struct {
	base, gcTransactionID string
	primary, gc           map[string]string
}

func loadAtomicTransformV2(path, stateDir string) (atomicTransformV2Loaded, error) {
	logical, fallbackBase, err := atomicTransformV2BasePath(path, stateDir)
	if err != nil {
		return atomicTransformV2Loaded{}, err
	}
	loadedNone := atomicTransformV2Loaded{base: fallbackBase, logical: logical}
	stateBound, err := bindAtomicTransformDirectory(stateDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return loadedNone, nil
		}
		return loadedNone, fmt.Errorf("bind stable compare-and-swap state directory: %w", err)
	}
	defer stateBound.Close()
	if err := stateBound.validatePrivate(); err != nil {
		return loadedNone, err
	}
	logical, primaryBase, err := atomicTransformV2BasePath(path, stateBound.path)
	if err != nil {
		return loadedNone, err
	}
	loadedNone = atomicTransformV2Loaded{base: primaryBase, logical: logical}

	groups := make([]atomicTransformV2CandidateGroup, 0, 4)
	matchingEntries := 0
	for {
		entries, readErr := stateBound.file.ReadDir(32)
		for _, entry := range entries {
			candidate, reserved, parseErr := parseAtomicTransformV2Candidate(entry.Name())
			if parseErr != nil {
				return loadedNone, parseErr
			}
			if !reserved {
				continue
			}
			matchingEntries++
			if matchingEntries > atomicTransformMaxIntentCandidates {
				return loadedNone, fmt.Errorf(
					"compare-and-swap recovery receipt candidate limit exceeded in %s", stateBound.path,
				)
			}
			candidateBasePath := filepath.Join(stateBound.path, candidate.base)
			index := -1
			for i := range groups {
				if atomicTransformPathsEqual(groups[i].base, candidateBasePath) {
					index = i
					break
				}
			}
			if index < 0 {
				groups = append(groups, atomicTransformV2CandidateGroup{
					base: candidateBasePath, primary: map[string]string{}, gc: map[string]string{},
				})
				index = len(groups) - 1
			}
			group := &groups[index]
			dest := group.primary
			if candidate.gc {
				dest = group.gc
				if group.gcTransactionID != "" && group.gcTransactionID != candidate.transactionID {
					return loadedNone, fmt.Errorf("multiple V2 CAS GC transaction identifiers claim %s", group.base)
				}
				group.gcTransactionID = candidate.transactionID
			}
			if previous := dest[candidate.phase]; previous != "" &&
				!atomicTransformPathsEqual(previous, entry.Name()) {
				return loadedNone, fmt.Errorf("multiple ordinal-equivalent %s V2 CAS receipts", candidate.phase)
			}
			dest[candidate.phase] = entry.Name()
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return loadedNone, fmt.Errorf("enumerate bound stable compare-and-swap receipts: %w", readErr)
		}
	}

	requestedInput, inputErr := canonicalAtomicTransformPath(path)
	if inputErr != nil {
		return loadedNone, inputErr
	}
	requestedLeaf := filepath.Base(requestedInput)
	requestedParentIdentity := ""
	// Bind the requested parent without resolving the leaf first. During a
	// ReplaceFileW/remove crash the recorded 8.3 leaf can be temporarily absent,
	// and resolving it would erase the only locator that can select its receipt.
	if parent, bindErr := bindAtomicTransformDirectory(filepath.Dir(requestedInput)); bindErr == nil {
		requestedParentIdentity = parent.identity
		_ = parent.Close()
	}
	// A successfully resolved canonical long leaf is only an additional match;
	// it must never be required for the missing-short-name recovery case.
	resolvedRequestedLeaf := ""
	if requested, resolveErr := resolveAtomicWritePath(path); resolveErr == nil {
		if requested, resolveErr = canonicalAtomicTransformTargetPath(requested); resolveErr == nil {
			resolvedRequestedLeaf = filepath.Base(requested)
		}
	}
	matched, matchedPriority := loadedNone, 0
	for _, group := range groups {
		candidate, candidateErr := loadAtomicTransformV2Group(group, stateBound)
		if candidateErr != nil {
			return candidate, candidateErr
		}
		if !candidate.exists {
			continue
		}
		priority := 0
		if atomicTransformPathsEqual(candidate.receipt.InputPath, requestedInput) {
			priority = 3
		} else if atomicTransformPathsEqual(candidate.logical, logical) {
			priority = 2
		} else if requestedParentIdentity != "" &&
			candidate.receipt.TargetParentIdentity == requestedParentIdentity &&
			(atomicTransformPathsEqual(filepath.Base(candidate.receipt.TargetPath), requestedLeaf) ||
				(candidate.receipt.TargetShortName != "" &&
					atomicTransformPathsEqual(candidate.receipt.TargetShortName, requestedLeaf)) ||
				(resolvedRequestedLeaf != "" &&
					atomicTransformPathsEqual(filepath.Base(candidate.receipt.TargetPath), resolvedRequestedLeaf))) {
			priority = 1
		}
		if priority == 0 || priority < matchedPriority {
			continue
		}
		if priority == matchedPriority && matched.exists {
			return loadedNone, fmt.Errorf(
				"multiple same-priority compare-and-swap recovery transactions claim %s: %s and %s",
				logical, matched.base, candidate.base,
			)
		}
		matched, matchedPriority = candidate, priority
	}
	if matched.exists && !matched.terminal.located && !matched.complete.located &&
		requestedParentIdentity == matched.receipt.TargetParentIdentity {
		requestedParent, bindErr := bindAtomicTransformDirectory(filepath.Dir(requestedInput))
		if bindErr != nil {
			return loadedNone, bindErr
		}
		requestedState, inspectErr := atomicTransformBoundInspect(
			requestedParent, requestedLeaf, atomicTransformMaxConfigBytes,
		)
		closeErr := requestedParent.Close()
		if inspectErr != nil || closeErr != nil {
			return loadedNone, errors.Join(inspectErr, closeErr)
		}
		if requestedState.exists {
			oldKnown := matched.receipt.OldExists &&
				atomicTransformV2KnownOldState(matched.receipt.Old, requestedState)
			newKnown := !matched.receipt.Remove &&
				atomicTransformV2PublishedTargetMatches(matched.receipt, requestedState)
			if !oldKnown && !newKnown {
				return loadedNone, fmt.Errorf(
					"requested recovery leaf is occupied by an unrecognized inode: %s",
					requestedInput,
				)
			}
		}
	}
	return matched, nil
}

func loadAtomicTransformV2Group(
	group atomicTransformV2CandidateGroup, stateDir *atomicTransformBoundDirectory,
) (atomicTransformV2Loaded, error) {
	loaded := atomicTransformV2Loaded{base: group.base}
	phases := []struct {
		name string
		dst  *atomicTransformV2PhaseReceipt
	}{
		{atomicTransformV2Allocation, &loaded.allocation},
		{atomicTransformV2Staging, &loaded.staging},
		{atomicTransformV2Prepared, &loaded.prepared},
		{atomicTransformV2Terminal, &loaded.terminal},
		{atomicTransformV2Complete, &loaded.complete},
	}
	var canonical *atomicTransformV2Receipt
	for _, phase := range phases {
		primaryName, gcName := group.primary[phase.name], group.gc[phase.name]
		phase.dst.path = atomicTransformV2ReceiptPath(group.base, phase.name)
		if primaryName != "" && gcName != "" {
			return loaded, fmt.Errorf("V2 CAS receipt exists at both primary and GC locations for %s", phase.name)
		}
		name, retired := primaryName, false
		if name == "" {
			name, retired = gcName, gcName != ""
		}
		if name == "" {
			continue
		}
		state, err := atomicTransformBoundInspectPrivate(stateDir, name, atomicTransformMaxIntentBytes)
		if err != nil || !state.exists {
			if err == nil {
				err = fmt.Errorf("compare-and-swap receipt disappeared while loading: %s", name)
			}
			return loaded, err
		}
		sourcePath := filepath.Join(stateDir.path, name)
		receipt, err := decodeAtomicTransformV2Receipt(state, sourcePath)
		if err != nil {
			return loaded, err
		}
		if receipt.Phase != phase.name {
			return loaded, fmt.Errorf("compare-and-swap receipt filename/phase mismatch: %s", sourcePath)
		}
		if retired && receipt.TransactionID != group.gcTransactionID {
			return loaded, fmt.Errorf("retired V2 CAS receipt filename does not bind its transaction")
		}
		owner, err := canonicalAtomicTransformPath(receipt.LogicalPath)
		if err != nil {
			return loaded, err
		}
		if err := validateAtomicTransformV2Receipt(receipt, owner, stateDir.path, group.base, sourcePath); err != nil {
			return loaded, err
		}
		if canonical != nil && !atomicTransformV2ReceiptEquivalent(*canonical, receipt) {
			return loaded, fmt.Errorf("compare-and-swap phase receipts describe different transactions")
		}
		copyReceipt := receipt
		canonical = &copyReceipt
		if retired {
			phase.dst.gcPath = sourcePath
		} else {
			phase.dst.path = sourcePath
			phase.dst.gcPath = sourcePath + ".gc-" + receipt.TransactionID
		}
		phase.dst.receipt = receipt
		phase.dst.state = state
		phase.dst.exists = !retired
		phase.dst.retired = retired
		phase.dst.located = true
		loaded.exists = true
		loaded.logical = owner
	}
	if canonical == nil {
		return loaded, nil
	}
	for _, phase := range []*atomicTransformV2PhaseReceipt{
		&loaded.allocation, &loaded.staging, &loaded.prepared, &loaded.terminal, &loaded.complete,
	} {
		if phase.gcPath == "" {
			phase.gcPath = phase.path + ".gc-" + canonical.TransactionID
		}
		if phase.located {
			loaded.receipt = phase.receipt
		}
	}
	loaded.gcOnly = loaded.complete.retired
	if loaded.gcOnly {
		complete := loaded.complete.receipt
		if loaded.staging.located && complete.StagingReceiptID != loaded.staging.state.identity {
			return loaded, fmt.Errorf("cleanup sentinel does not bind located staging receipt")
		}
		if loaded.prepared.located && complete.PreparedReceiptID != loaded.prepared.state.identity {
			return loaded, fmt.Errorf("cleanup sentinel does not bind located prepared receipt")
		}
		if loaded.terminal.located && (complete.TerminalReceiptID != loaded.terminal.state.identity ||
			complete.Decision != loaded.terminal.receipt.Decision) {
			return loaded, fmt.Errorf("cleanup sentinel does not bind located terminal receipt")
		}
		return loaded, nil
	}
	if loaded.prepared.located && (!loaded.staging.located ||
		loaded.prepared.receipt.StagingReceiptID != loaded.staging.state.identity) {
		return loaded, fmt.Errorf("prepared receipt does not bind the exact staging receipt")
	}
	if loaded.terminal.located && (!loaded.staging.located || !loaded.prepared.located ||
		loaded.terminal.receipt.StagingReceiptID != loaded.staging.state.identity ||
		loaded.terminal.receipt.PreparedReceiptID != loaded.prepared.state.identity) {
		return loaded, fmt.Errorf("terminal receipt does not bind its exact prior receipts")
	}
	if loaded.complete.located {
		complete := loaded.complete.receipt
		if complete.StagingReceiptID == "" || (loaded.staging.located &&
			complete.StagingReceiptID != loaded.staging.state.identity) {
			return loaded, fmt.Errorf("complete receipt does not bind the exact staging receipt")
		}
		if complete.PreparedReceiptID == "" {
			if loaded.prepared.located || loaded.terminal.located ||
				complete.Decision != atomicTransformV2DecisionAbort {
				return loaded, fmt.Errorf("staging-only complete receipt has an invalid phase chain")
			}
		} else {
			if (loaded.prepared.located && complete.PreparedReceiptID != loaded.prepared.state.identity) ||
				(loaded.terminal.located && (complete.TerminalReceiptID != loaded.terminal.state.identity ||
					complete.Decision != loaded.terminal.receipt.Decision)) {
				return loaded, fmt.Errorf("complete receipt does not bind the exact terminal chain")
			}
		}
		if !loaded.complete.retired {
			if !loaded.staging.located || (complete.PreparedReceiptID != "" &&
				(!loaded.prepared.located || !loaded.terminal.located)) {
				return loaded, fmt.Errorf("complete primary is missing its primary-or-GC receipt chain")
			}
		}
	} else {
		if loaded.terminal.located && (!loaded.prepared.located || !loaded.staging.located) {
			return loaded, fmt.Errorf("terminal receipt exists without its staging/prepared chain")
		}
		if loaded.prepared.located && !loaded.staging.located {
			return loaded, fmt.Errorf("prepared receipt exists without its staging locator")
		}
	}
	return loaded, nil
}

func recoverAtomicTransformV2(path, stateDir string) error {
	if err := atomicTransformValidateNoReparsePathPlatform(stateDir); err != nil {
		return err
	}
	return withAtomicTransformV2ProtocolLock(path, stateDir, func() error {
		return recoverAtomicTransformV2Locked(path, stateDir)
	}, nil)
}

func recoverAtomicTransformV2Locked(path, stateDir string) error {
	// V2 terminal and complete receipts are authoritative: once either exists,
	// no legacy recovery is allowed to mutate the live target. Inspect both
	// namespaces before every transition and fail closed if independently valid
	// V1 and V2 transactions claim the same logical path. Advancing legacy
	// recovery one transition at a time also closes the upgrade window in which
	// V2 could appear between a monolithic V1 recovery and the next V2 load.
	for pass := 0; pass < 24; pass++ {
		loaded, err := loadAtomicTransformV2(path, stateDir)
		if err != nil {
			return err
		}
		trustedTargetParent := ""
		if loaded.exists {
			// Receipt loading authenticates this physical target owner. Use its
			// recorded parent to locate a target-local V1 namespace; deriving that
			// directory from the current live leaf could follow an operator reparse
			// point after P.
			trustedTargetParent = filepath.Dir(loaded.receipt.TargetPath)
		}
		legacyDir, legacyExists, err := loadAtomicTransformV1ForV2Migration(
			path, stateDir, trustedTargetParent,
		)
		if err != nil {
			return err
		}
		if loaded.exists && legacyExists {
			return fmt.Errorf(
				"both V1 and V2 compare-and-swap recovery namespaces claim %s; refusing to mutate live state",
				loaded.logical,
			)
		}
		if !loaded.exists {
			if legacyExists {
				// V1 recovery can mutate live and has no receipt-bound Windows
				// directory handles. Keep its historical full-path no-reparse gate;
				// only V2 terminal/complete/GC cleanup may ignore the live leaf.
				if err := atomicTransformValidateNoReparsePathPlatform(path); err != nil {
					return fmt.Errorf("validate Windows config locator before legacy recovery: %w", err)
				}
				// Recheck V2 immediately before the only legacy operation that may
				// mutate live state. The protected state directory and connector
				// advisory lock exclude untrusted/conforming concurrent publishers;
				// this second read catches an independently started V2 transaction.
				recheck, recheckErr := loadAtomicTransformV2(path, stateDir)
				if recheckErr != nil {
					return recheckErr
				}
				if recheck.exists {
					return fmt.Errorf(
						"V2 compare-and-swap recovery appeared while legacy recovery was pending for %s; refusing to mutate live state",
						recheck.logical,
					)
				}
				if err := recoverAtomicTransformOnce(path, legacyDir); err != nil {
					return fmt.Errorf("recover legacy compare-and-swap transaction before V2: %w", err)
				}
				continue
			}
			// Prove the V2 namespace is still empty after legacy convergence.
			// atomicTransformFileV2 may now start Rs; its no-replace publication
			// remains the final arbiter against another conforming process.
			recheck, recheckErr := loadAtomicTransformV2(path, stateDir)
			if recheckErr != nil {
				return recheckErr
			}
			if recheck.exists {
				continue
			}
			return nil
		}
		switch {
		case loaded.complete.located:
			if err := retireAtomicTransformV2Receipts(loaded); err != nil {
				return err
			}
		case loaded.terminal.located:
			if err := completeCommittedAtomicTransformV2(loaded); err != nil {
				return err
			}
		case loaded.prepared.located:
			if err := recoverPreparedAtomicTransformV2(loaded); err != nil {
				return err
			}
		case loaded.staging.located:
			if err := abortAtomicTransformV2(loaded); err != nil {
				return err
			}
		case loaded.allocation.located:
			if err := abortAtomicTransformV2Allocation(loaded); err != nil {
				return err
			}
		default:
			return fmt.Errorf("compare-and-swap recovery has no recognized phase")
		}
	}
	return fmt.Errorf("compare-and-swap recovery did not converge after bounded V1/V2 phase transitions")
}

// loadAtomicTransformV1ForV2Migration discovers both V1 namespaces that can
// exist during an upgrade: the stable directory supplied by the V2 caller and
// the target-local directory used by previously shipped code. It never creates
// the target-local directory. A valid transaction in more than one namespace
// is ambiguous and therefore fails closed.
func loadAtomicTransformV1ForV2Migration(
	path, stableStateDir, trustedTargetParent string,
) (string, bool, error) {
	stableStateDir, err := canonicalAtomicTransformPath(stableStateDir)
	if err != nil {
		return "", false, err
	}
	if trustedTargetParent == "" {
		requestedParent, parentErr := canonicalAtomicTransformPath(filepath.Dir(path))
		if parentErr != nil {
			return "", false, parentErr
		}
		if parentErr = atomicTransformValidateNoReparsePathPlatform(requestedParent); parentErr != nil {
			return "", false, parentErr
		}
		parent, bindErr := bindAtomicTransformDirectory(requestedParent)
		if errors.Is(bindErr, os.ErrNotExist) {
			// A first-time create has no target parent and therefore cannot have
			// the historical target-local V1 namespace. Keep scanning the stable
			// state directory below; do not create the target parent during
			// recovery discovery or fail before V2 can create it normally.
			trustedTargetParent = ""
		} else if bindErr != nil {
			return "", false, bindErr
		} else {
			trustedTargetParent = parent.path
			if closeErr := parent.Close(); closeErr != nil {
				return "", false, closeErr
			}
		}
	} else {
		trustedTargetParent, err = canonicalAtomicTransformPath(trustedTargetParent)
		if err != nil {
			return "", false, err
		}
		if err := atomicTransformValidateNoReparsePathPlatform(trustedTargetParent); err != nil {
			return "", false, err
		}
	}
	directories := []string{stableStateDir}
	if trustedTargetParent != "" {
		legacyStateDir, legacyErr := canonicalAtomicTransformPath(
			filepath.Join(trustedTargetParent, ".defenseclaw-cas-state"),
		)
		if legacyErr != nil {
			return "", false, legacyErr
		}
		if !atomicTransformLocationsEquivalent(stableStateDir, legacyStateDir) {
			directories = append(directories, legacyStateDir)
		}
	}

	matchedDir := ""
	for _, directory := range directories {
		bound, bindErr := bindAtomicTransformDirectory(directory)
		if errors.Is(bindErr, os.ErrNotExist) {
			continue
		}
		if bindErr != nil {
			return "", false, fmt.Errorf("bind legacy compare-and-swap state directory %s: %w", directory, bindErr)
		}
		if privateErr := bound.validatePrivate(); privateErr != nil {
			_ = bound.Close()
			return "", false, fmt.Errorf("validate legacy compare-and-swap state directory %s: %w", directory, privateErr)
		}
		loaded, loadErr := loadAtomicTransformIntentWithStates(path, bound.path)
		closeErr := bound.Close()
		if loadErr != nil || closeErr != nil {
			return "", false, errors.Join(loadErr, closeErr)
		}
		if !loaded.exists {
			continue
		}
		if matchedDir != "" {
			return "", false, fmt.Errorf(
				"multiple V1 compare-and-swap recovery namespaces claim %s: %s and %s",
				loaded.logical, matchedDir, bound.path,
			)
		}
		matchedDir = bound.path
	}
	return matchedDir, matchedDir != "", nil
}

func bindAtomicTransformV2ReceiptDirectories(
	receipt atomicTransformV2Receipt,
) (*atomicTransformBoundDirectory, *atomicTransformBoundDirectory, error) {
	targetDir, err := bindAtomicTransformDirectory(filepath.Dir(receipt.TargetPath))
	if err != nil {
		return nil, nil, err
	}
	if targetDir.identity != receipt.TargetParentIdentity {
		_ = targetDir.Close()
		return nil, nil, fmt.Errorf("target parent changed identity; retaining compare-and-swap receipts")
	}
	stateDir, err := bindAtomicTransformDirectory(receipt.StateDir)
	if err != nil {
		_ = targetDir.Close()
		return nil, nil, err
	}
	if stateDir.identity != receipt.StateDirIdentity {
		_ = targetDir.Close()
		_ = stateDir.Close()
		return nil, nil, fmt.Errorf("stable state directory changed identity; retaining compare-and-swap receipts")
	}
	if err := stateDir.validatePrivate(); err != nil {
		_ = targetDir.Close()
		_ = stateDir.Close()
		return nil, nil, err
	}
	return targetDir, stateDir, nil
}

func commitAtomicTransformV2(
	path string, snapshot atomicFileSnapshot, txn *atomicTransformV2Transaction,
) error {
	receipt := txn.receipt
	if err := txn.targetDir.validate(); err != nil {
		return err
	}
	if err := txn.stateDir.validatePrivate(); err != nil {
		return err
	}
	resolved, err := resolveAtomicWritePath(path)
	if err == nil {
		resolved, err = canonicalAtomicTransformTargetPath(resolved)
	}
	if err != nil || !atomicTransformPathsEqual(resolved, receipt.TargetPath) {
		return errAtomicTransformConflict
	}
	if receipt.OldExists {
		if err := commitAtomicTransformV2ExistingPlatform(path, snapshot, txn); err != nil {
			return err
		}
	} else {
		targetName := filepath.Base(receipt.TargetPath)
		targetState, err := atomicTransformBoundInspect(txn.targetDir, targetName, atomicTransformMaxConfigBytes)
		if err != nil {
			return err
		}
		if targetState.exists {
			return errAtomicTransformConflict
		}
		stageState, err := atomicTransformBoundInspectFilePrivate(txn.targetDir, receipt.StageFinalName, atomicTransformMaxConfigBytes)
		if err != nil || !atomicTransformV2StateMatches(receipt.Stage, stageState, true) {
			if err == nil {
				err = fmt.Errorf("prepared stage changed before create publication")
			}
			return err
		}
		if _, err := atomicTransformBoundRenameNoReplace(
			txn.targetDir, receipt.StageFinalName, targetName, stageState,
		); err != nil {
			return err
		}
		if err := runAtomicTransformPhaseHook(path, atomicTransformPhasePublished, atomicTransformV2HookState(txn.base, receipt)); err != nil {
			return err
		}
	}
	if err := validateAtomicTransformV2CommittedPostcondition(txn.targetDir, receipt); err != nil {
		return err
	}
	// Durable final publication validation is P: the exact namespace result has
	// already been flushed, its parent synchronized, and any recorded short alias
	// repaired and verified. Rt only authorizes recovery/cleanup. This seam proves
	// that edits at or after P remain operator-owned.
	if err := runAtomicTransformPhaseHook(
		path, atomicTransformPhaseFinalPublicationValidated,
		atomicTransformV2HookState(txn.base, receipt),
	); err != nil {
		return err
	}
	// Do not re-resolve the caller locator after P. The bound physical
	// TargetPath was validated before publication; a later alias/parent retarget
	// is ordered after P and cannot revoke or roll back that publication.
	if err := txn.targetDir.validate(); err != nil {
		return fmt.Errorf("target parent detached before terminal authorization: %w", err)
	}
	if err := txn.stateDir.validatePrivate(); err != nil {
		return fmt.Errorf("state directory changed before terminal authorization: %w", err)
	}
	receipt.StagingReceiptID = txn.stagingState.identity
	receipt.PreparedReceiptID = txn.preparedState.identity
	receipt.Decision = atomicTransformV2DecisionCommit
	terminalState, err := persistAtomicTransformV2Receipt(
		txn.stateDir, txn.base, receipt, atomicTransformV2Terminal,
	)
	if err != nil {
		return err
	}
	receipt.Phase = atomicTransformV2Terminal
	txn.receipt = receipt
	if err := runAtomicTransformPhaseHook(path, atomicTransformPhaseTerminalWitnessed, atomicTransformV2HookState(txn.base, receipt)); err != nil {
		return err
	}
	_ = terminalState
	return nil
}

func validateAtomicTransformV2CommittedPostcondition(
	dir *atomicTransformBoundDirectory, receipt atomicTransformV2Receipt,
) error {
	targetName := filepath.Base(receipt.TargetPath)
	target, err := atomicTransformBoundInspect(dir, targetName, atomicTransformMaxConfigBytes)
	if err != nil {
		return err
	}
	if receipt.OldExists {
		tomb, tombErr := atomicTransformBoundInspect(
			dir, receipt.TombstoneName, atomicTransformMaxConfigBytes,
		)
		if tombErr != nil {
			return tombErr
		}
		if !atomicTransformV2KnownOldState(receipt.Old, tomb) {
			return fmt.Errorf("%w: exact prior-config publication witness is unavailable", errAtomicTransformConflict)
		}
	}
	if receipt.Remove {
		if target.exists {
			return fmt.Errorf("%w: live target was recreated before durable final publication validation", errAtomicTransformConflict)
		}
		return nil
	}
	if !atomicTransformV2PublishedTargetMatches(receipt, target) {
		return fmt.Errorf("%w: published config changed before durable terminal authorization", errAtomicTransformConflict)
	}
	if receipt.RequestedPrivate {
		privateTarget, privateErr := atomicTransformBoundInspectFilePrivate(
			dir, targetName, atomicTransformMaxConfigBytes,
		)
		if privateErr != nil || !atomicTransformV2PublishedTargetMatches(receipt, privateTarget) {
			if privateErr == nil {
				privateErr = fmt.Errorf("published config lost its requested private protection")
			}
			return fmt.Errorf("%w: %v", errAtomicTransformConflict, privateErr)
		}
	}
	return nil
}

func atomicTransformV2EstablishMarker(
	dir *atomicTransformBoundDirectory,
	receipt atomicTransformV2Receipt,
	destination string,
	marker atomicTransformV2Artifact,
	allowed atomicTransformV2Artifact,
	allowPartial bool,
) error {
	source, err := atomicTransformBoundInspectFilePrivate(dir, marker.Name, atomicTransformMaxIntentBytes)
	if err != nil {
		return err
	}
	destinationState, err := atomicTransformBoundInspect(dir, destination, atomicTransformMaxConfigBytes)
	if err != nil {
		return err
	}
	if atomicTransformV2RenamedArtifactMatches(marker, destinationState) {
		if source.exists {
			return fmt.Errorf("harmless marker exists at both source and destination; retaining receipts")
		}
		privateDestination, privateErr := atomicTransformBoundInspectFilePrivate(
			dir, destination, atomicTransformMaxIntentBytes,
		)
		if privateErr != nil || !atomicTransformV2RenamedArtifactMatches(marker, privateDestination) {
			if privateErr == nil {
				privateErr = fmt.Errorf("harmless marker destination is not exact private data: %s", destination)
			}
			return privateErr
		}
		return nil
	}
	if !atomicTransformV2StateMatches(marker, source, true) {
		return fmt.Errorf("harmless marker source changed or disappeared: %s", marker.Name)
	}
	if destinationState.exists {
		allowedMatch := atomicTransformV2StateMatches(allowed, destinationState, !allowPartial)
		if !allowedMatch && allowed.Identity == receipt.Old.Identity {
			allowedMatch = atomicTransformV2KnownOldState(receipt.Old, destinationState)
		}
		if !allowedMatch && allowed.Identity == receipt.Stage.Identity {
			// ReplaceFileW may merge Old's metadata onto the exact Stage inode.
			// Identity plus immutable main-stream bytes remains the transaction
			// witness; protection is separately constrained by RequestedPrivate.
			allowedMatch = atomicTransformV2KnownStageState(receipt, destinationState)
		}
		if !allowedMatch {
			return fmt.Errorf("foreign artifact occupies compare-and-swap marker slot: %s", destination)
		}
		if err := atomicTransformBoundDeleteExact(dir, destination, destinationState); err != nil {
			return err
		}
		if err := runAtomicTransformPhaseHook(
			receipt.LogicalPath,
			atomicTransformPhaseCleanupStarted,
			atomicTransformV2HookState(atomicTransformV2ReceiptPathForReceipt(receipt), receipt),
		); err != nil {
			return err
		}
	}
	published, err := atomicTransformBoundRenameNoReplace(dir, marker.Name, destination, source)
	if err != nil {
		return err
	}
	if !atomicTransformV2RenamedArtifactMatches(marker, published) {
		return fmt.Errorf("harmless marker did not occupy exact recorded slot: %s", destination)
	}
	privatePublished, err := atomicTransformBoundInspectFilePrivate(dir, destination, atomicTransformMaxIntentBytes)
	if err != nil || !atomicTransformV2RenamedArtifactMatches(marker, privatePublished) {
		if err == nil {
			err = fmt.Errorf("published harmless marker is not exact private data: %s", destination)
		}
		return err
	}
	return runAtomicTransformPhaseHook(
		receipt.LogicalPath, atomicTransformPhaseMarkerEstablished,
		atomicTransformV2HookState(atomicTransformV2ReceiptPathForReceipt(receipt), receipt),
	)
}

func atomicTransformV2ReceiptPathForReceipt(receipt atomicTransformV2Receipt) string {
	_, base, err := atomicTransformV2BasePath(receipt.LogicalPath, receipt.StateDir)
	if err != nil {
		return ""
	}
	return base
}

func establishAtomicTransformV2StageMarkers(
	dir *atomicTransformBoundDirectory, receipt atomicTransformV2Receipt,
) error {
	if receipt.Remove {
		return nil
	}
	if err := atomicTransformV2EstablishMarker(
		dir, receipt, receipt.Stage.Name, receipt.StageMarker, receipt.Stage, true,
	); err != nil {
		return err
	}
	return atomicTransformV2EstablishMarker(
		dir, receipt, receipt.StageFinalName, receipt.FinalMarker, receipt.Stage, true,
	)
}

func establishAtomicTransformV2TerminalMarker(
	dir *atomicTransformBoundDirectory, receipt atomicTransformV2Receipt,
) error {
	allowed := atomicTransformV2Artifact{}
	if receipt.OldExists {
		allowed = receipt.Old
	}
	return atomicTransformV2EstablishMarker(
		dir, receipt, receipt.TerminalMarkerName, receipt.TerminalMarker, allowed, false,
	)
}

func completeCommittedAtomicTransformV2(loaded atomicTransformV2Loaded) error {
	targetDir, stateDir, err := bindAtomicTransformV2ReceiptDirectories(loaded.receipt)
	if err != nil {
		return err
	}
	defer targetDir.Close()
	defer stateDir.Close()
	receipt := loaded.receipt
	// Durable final publication/rollback validation is the live-data
	// linearization point P. Rt is only the decision fence; completion may
	// sanitize exact transaction side slots and receipts but never live.
	if err := establishAtomicTransformV2StageMarkers(targetDir, receipt); err != nil {
		return err
	}
	if err := establishAtomicTransformV2TerminalMarker(targetDir, receipt); err != nil {
		return err
	}
	receipt.StagingReceiptID = loaded.staging.state.identity
	receipt.PreparedReceiptID = loaded.prepared.state.identity
	receipt.TerminalReceiptID = loaded.terminal.state.identity
	if _, err := persistAtomicTransformV2Receipt(
		stateDir, loaded.base, receipt, atomicTransformV2Complete,
	); err != nil {
		return err
	}
	receipt.Phase = atomicTransformV2Complete
	return runAtomicTransformPhaseHook(
		receipt.LogicalPath, atomicTransformPhaseCompleted, atomicTransformV2HookState(loaded.base, receipt),
	)
}

func recoverPreparedAtomicTransformV2(loaded atomicTransformV2Loaded) error {
	targetDir, stateDir, err := bindAtomicTransformV2ReceiptDirectories(loaded.receipt)
	if err != nil {
		return err
	}
	defer targetDir.Close()
	defer stateDir.Close()
	receipt := loaded.receipt
	// Recovery is receipt-bound. A post-publication logical alias retarget or a
	// temporarily missing 8.3 leaf cannot revoke P or redirect these operations;
	// TargetPath and its recorded parent identity are the only authority here.
	targetName := filepath.Base(receipt.TargetPath)
	target, err := atomicTransformBoundInspect(targetDir, targetName, atomicTransformMaxConfigBytes)
	if err != nil {
		return err
	}
	tomb := atomicTransformArtifactState{}
	if receipt.TombstoneName != "" {
		tomb, err = atomicTransformBoundInspect(targetDir, receipt.TombstoneName, atomicTransformMaxConfigBytes)
		if err != nil {
			return err
		}
	}
	stage := atomicTransformArtifactState{}
	if receipt.StageFinalName != "" {
		// ReplaceFileW may merge Old's custom DACL into Stage. Inspect generically
		// so the classifier can recognize a documented partial result while
		// preserving every unrecognized inode fail-closed. Privacy is enforced
		// separately for exact transaction-owned artifacts when requested.
		stage, err = atomicTransformBoundInspect(targetDir, receipt.StageFinalName, atomicTransformMaxConfigBytes)
		if err != nil {
			return err
		}
	}
	provisional := atomicTransformArtifactState{}
	if receipt.Stage.Name != "" {
		provisional, err = atomicTransformBoundInspectFilePrivate(targetDir, receipt.Stage.Name, atomicTransformMaxConfigBytes)
		if err != nil {
			return err
		}
	}
	tombOld := receipt.OldExists && atomicTransformV2KnownOldState(receipt.Old, tomb)
	targetNew := !receipt.Remove && atomicTransformV2PublishedTargetMatches(receipt, target)
	stageNew := !receipt.Remove && atomicTransformV2KnownStageState(receipt, stage)
	provisionalNew := !receipt.Remove && atomicTransformV2StateMatches(receipt.Stage, provisional, true)
	provisionalMarker := !receipt.Remove && atomicTransformV2RenamedArtifactMatches(receipt.StageMarker, provisional)
	finalMarker := !receipt.Remove && atomicTransformV2RenamedArtifactMatches(receipt.FinalMarker, stage)
	terminalMarker := atomicTransformV2RenamedArtifactMatches(receipt.TerminalMarker, tomb)
	progress := func(boundary string) error {
		return runAtomicTransformPhaseHook(
			receipt.LogicalPath, atomicTransformPhase("replace-"+boundary),
			atomicTransformV2HookState(loaded.base, receipt),
		)
	}
	authorizeCommit := func() error {
		if err := validateAtomicTransformV2CommittedPostcondition(targetDir, receipt); err != nil {
			return err
		}
		if err := runAtomicTransformPhaseHook(
			receipt.LogicalPath, atomicTransformPhaseFinalPublicationValidated,
			atomicTransformV2HookState(loaded.base, receipt),
		); err != nil {
			return err
		}
		receipt.StagingReceiptID = loaded.staging.state.identity
		receipt.PreparedReceiptID = loaded.prepared.state.identity
		receipt.Decision = atomicTransformV2DecisionCommit
		if _, persistErr := persistAtomicTransformV2Receipt(
			stateDir, loaded.base, receipt, atomicTransformV2Terminal,
		); persistErr != nil {
			return persistErr
		}
		receipt.Phase = atomicTransformV2Terminal
		return runAtomicTransformPhaseHook(
			receipt.LogicalPath, atomicTransformPhaseTerminalWitnessed,
			atomicTransformV2HookState(loaded.base, receipt),
		)
	}
	if receipt.OldExists && !receipt.Remove {
		observed := atomicTransformV2ReplaceObservation{Target: target, Backup: tomb, Stage: stage}
		if repaired, repairErr := repairAtomicTransformV2ReplacementDACL(
			targetDir, receipt, observed,
		); repairErr != nil {
			return repairErr
		} else if repaired {
			observed, err = observeAtomicTransformV2Replacement(targetDir, receipt)
			if err != nil {
				return err
			}
			target, tomb, stage = observed.Target, observed.Backup, observed.Stage
			tombOld = atomicTransformV2KnownOldState(receipt.Old, tomb)
			targetNew = atomicTransformV2PublishedTargetMatches(receipt, target)
			stageNew = atomicTransformV2KnownStageState(receipt, stage)
		}
		switch classifyAtomicTransformV2ReplaceObservation(
			receipt, atomicTransformV2ReplaceOtherFailure, observed,
		) {
		case atomicTransformV2ReplaceReadyForPublication:
			if err := flushAtomicTransformV2ReplacementForPublication(
				targetDir, receipt, observed, progress,
			); err != nil {
				return err
			}
			if err := repairAtomicTransformV2ReplacementShortName(
				targetDir, targetName, receipt.TombstoneName,
				receipt.TargetShortName, receipt.StageShortName,
				observed.Target, observed.Backup, progress,
			); err != nil {
				return err
			}
			// Reinspect after flush/short-name durability. The generic publication
			// branch below performs the logical-locator check before authorizing Rt.
			target, err = atomicTransformBoundInspect(targetDir, targetName, atomicTransformMaxConfigBytes)
			if err != nil {
				return err
			}
			tomb, err = atomicTransformBoundInspect(targetDir, receipt.TombstoneName, atomicTransformMaxConfigBytes)
			if err != nil {
				return err
			}
			stage, err = atomicTransformBoundInspect(targetDir, receipt.StageFinalName, atomicTransformMaxConfigBytes)
			if err != nil {
				return err
			}
			tombOld = atomicTransformV2KnownOldState(receipt.Old, tomb)
			targetNew = atomicTransformV2PublishedTargetMatches(receipt, target)
			stageNew = atomicTransformV2KnownStageState(receipt, stage)
		case atomicTransformV2ReplaceRestoreOldThenRetry:
			if err := restoreAtomicTransformV2Replace1177(targetDir, receipt, observed, progress); err != nil {
				return err
			}
			return nil
		}
	}

	// Exact New at live with both stage names consumed and the authenticated Old
	// tomb proves publication of an existing target. The tomb is part of the
	// final publication witness: deleting it before P is an unordered namespace
	// mutation, not permission to infer commit. Creates have no Old witness.
	replacementCommitted := !receipt.Remove && targetNew &&
		!stage.exists && !provisional.exists && (!receipt.OldExists || tombOld)
	// Remove can reach final publication validation only with live absent plus the
	// authenticated Old tomb. Mere absence could be an unordered operator delete
	// and is never enough to establish P or authorize Rt.
	removeCommitted := receipt.Remove && !target.exists && tombOld
	if replacementCommitted || removeCommitted {
		// The receipt's bound physical TargetPath and parent identity, not a
		// subsequently retargetable lexical alias, authorize final validation.
		return authorizeCommit()
	}
	if !receipt.Remove && tombOld && !stage.exists && !provisional.exists && !targetNew {
		// Rp proves ReplaceFileW moved exact Old, but it cannot prove whether a
		// changed/foreign/absent live state was modified before or after the call.
		// Before durable Rt there is no operator-authoritative ordering witness.
		return fmt.Errorf(
			"ambiguous ReplaceFileW result has exact prior backup but no exact Stage payload at live; retaining recovery artifacts",
		)
	}

	// A detached exact prior object must be restored before Rt(false). If an
	// editor already supplied a new live target, preserve it. Exact tomb/stage
	// sanitation is deferred until after Rt(abort).
	if !target.exists && tombOld {
		if !receipt.Remove && !stageNew {
			return fmt.Errorf(
				"ambiguous replacement was published then removed before terminal authorization; preserving live absence and recovery tombstone",
			)
		}
		if _, err := atomicTransformBoundRenameNoReplace(
			targetDir, receipt.TombstoneName, targetName, tomb,
		); err != nil {
			return err
		}
		target = tomb
		tomb = atomicTransformArtifactState{}
		tombOld = false
	}

	if tomb.exists && !tombOld && !terminalMarker {
		return fmt.Errorf("foreign artifact occupies prepared abort tombstone slot")
	}
	if !receipt.Remove {
		provisionalOwned := !provisional.exists || provisionalNew || provisionalMarker
		finalOwned := !stage.exists || stageNew || finalMarker
		if !provisionalOwned || !finalOwned {
			return fmt.Errorf("foreign artifact occupies prepared abort stage slot")
		}
		if targetNew {
			return fmt.Errorf("exact published config has an ambiguous occupied rollback slot; retaining prepared receipt")
		}
	}
	if receipt.OldExists && !target.exists {
		return fmt.Errorf("prepared abort cannot establish an authoritative live state; retaining recovery artifacts")
	}
	return abortAtomicTransformV2Bound(loaded, targetDir, stateDir)
}

func abortAtomicTransformV2(loaded atomicTransformV2Loaded) error {
	targetDir, stateDir, err := bindAtomicTransformV2ReceiptDirectories(loaded.receipt)
	if err != nil {
		return err
	}
	defer targetDir.Close()
	defer stateDir.Close()
	return abortAtomicTransformV2Bound(loaded, targetDir, stateDir)
}

func inspectAtomicTransformV2HarmlessAllocationArtifact(
	dir *atomicTransformBoundDirectory, name string, expected []byte,
) (atomicTransformArtifactState, error) {
	file, err := openAtomicTransformBoundFilePlatform(dir.file, name, false)
	if errors.Is(err, os.ErrNotExist) {
		return atomicTransformArtifactState{}, nil
	}
	if err != nil {
		return atomicTransformArtifactState{}, err
	}
	defer file.Close()
	if err := validateAtomicTransformBoundFilePrivatePlatform(file); err != nil {
		return atomicTransformArtifactState{}, err
	}
	state, err := atomicTransformBoundStateFromOpen(file, name, atomicTransformMaxIntentBytes)
	if err != nil {
		return atomicTransformArtifactState{}, err
	}
	witness, err := atomicTransformV2WindowsMetadataFromOpen(file)
	if err != nil {
		return atomicTransformArtifactState{}, err
	}
	harmlessAttributes := witness.FileAttributes &^
		(windows.FILE_ATTRIBUTE_ARCHIVE | windows.FILE_ATTRIBUTE_NORMAL)
	harmlessMain := len(witness.Streams) == 1 &&
		witness.Streams[0].ID == atomicTransformV2BackupData &&
		witness.Streams[0].Name == "" && witness.Streams[0].Size == int64(len(expected)) &&
		witness.Streams[0].SHA256 == atomicTransformDigest(expected)
	if state.linkCount != 1 || state.info.Mode()&os.ModeType != 0 ||
		state.size != int64(len(expected)) || !bytes.Equal(state.data, expected) ||
		witness.Compression != 0 || harmlessAttributes != 0 || !harmlessMain {
		return atomicTransformArtifactState{}, fmt.Errorf(
			"allocation-authenticated artifact has non-harmless metadata; preserving it fail-closed: %s",
			name,
		)
	}
	return state, nil
}

func abortAtomicTransformV2Allocation(loaded atomicTransformV2Loaded) error {
	if !loaded.allocation.located || loaded.staging.located || loaded.prepared.located ||
		loaded.terminal.located || loaded.complete.located {
		return fmt.Errorf("allocation cleanup requires an allocation-only transaction")
	}
	targetDir, stateDir, err := bindAtomicTransformV2ReceiptDirectories(loaded.receipt)
	if err != nil {
		return err
	}
	defer targetDir.Close()
	defer stateDir.Close()
	receipt := loaded.allocation.receipt
	artifacts := []struct {
		name, label string
	}{
		{receipt.TerminalMarker.Name, "terminal"},
	}
	if !receipt.Remove {
		artifacts = append(artifacts,
			struct{ name, label string }{receipt.Stage.Name, "payload"},
			struct{ name, label string }{receipt.StageMarker.Name, "stage"},
			struct{ name, label string }{receipt.FinalMarker.Name, "ready"},
		)
	}
	for _, artifact := range artifacts {
		expected := atomicTransformV2MarkerBytes(receipt.TransactionID, artifact.label)
		state, inspectErr := inspectAtomicTransformV2HarmlessAllocationArtifact(
			targetDir, artifact.name, expected,
		)
		if inspectErr != nil {
			return inspectErr
		}
		if !state.exists {
			continue
		}
		if err := atomicTransformBoundDeleteExact(targetDir, artifact.name, state); err != nil {
			return err
		}
	}
	name := filepath.Base(loaded.allocation.path)
	state, err := atomicTransformBoundInspectPrivate(stateDir, name, atomicTransformMaxIntentBytes)
	if err != nil {
		return err
	}
	if !state.exists || !atomicTransformArtifactStatesEqualExact(state, loaded.allocation.state) {
		return fmt.Errorf("allocation receipt changed before exact retirement")
	}
	return atomicTransformBoundDeleteExact(stateDir, name, state)
}

func abortAtomicTransformV2Bound(
	loaded atomicTransformV2Loaded,
	targetDir, stateDir *atomicTransformBoundDirectory,
) error {
	receipt := loaded.receipt
	if loaded.prepared.exists && !loaded.terminal.exists {
		if receipt.OldExists {
			targetName := filepath.Base(receipt.TargetPath)
			target, err := atomicTransformBoundInspect(
				targetDir, targetName, atomicTransformMaxConfigBytes,
			)
			if err != nil {
				return err
			}
			if !atomicTransformV2KnownOldState(receipt.Old, target) {
				return fmt.Errorf("exact prior config is not live before durable abort authorization")
			}
			progress := func(boundary string) error {
				return runAtomicTransformPhaseHook(
					receipt.LogicalPath, atomicTransformPhase("replace-"+boundary),
					atomicTransformV2HookState(loaded.base, receipt),
				)
			}
			if err := repairAtomicTransformV2ReplacementShortName(
				targetDir, targetName, receipt.TombstoneName,
				receipt.TargetShortName, "", target, atomicTransformArtifactState{}, progress,
			); err != nil {
				return err
			}
		}
		if err := runAtomicTransformPhaseHook(
			receipt.LogicalPath, atomicTransformPhaseFinalPublicationValidated,
			atomicTransformV2HookState(loaded.base, receipt),
		); err != nil {
			return err
		}
		// The caller has completed any necessary live rollback. Publish Rt(abort)
		// before discarding Old or sanitizing any stage slot. Live remains
		// operator-authoritative after durable abort validation; completion cleans
		// only exact transaction-owned side artifacts.
		receipt.Decision = atomicTransformV2DecisionAbort
		receipt.StagingReceiptID = loaded.staging.state.identity
		receipt.PreparedReceiptID = loaded.prepared.state.identity
		if _, err := persistAtomicTransformV2Receipt(
			stateDir, loaded.base, receipt, atomicTransformV2Terminal,
		); err != nil {
			return err
		}
		receipt.Phase = atomicTransformV2Terminal
		return runAtomicTransformPhaseHook(
			receipt.LogicalPath, atomicTransformPhaseTerminalWitnessed,
			atomicTransformV2HookState(loaded.base, receipt),
		)
	}
	// Rs-only abort has never touched live. Rc itself is the durable cleanup
	// authorization; marker sanitation is deferred until Rc is first retired to
	// its cleanup-only sentinel.
	receipt.Decision = atomicTransformV2DecisionAbort
	if loaded.staging.exists {
		receipt.StagingReceiptID = loaded.staging.state.identity
	}
	if loaded.prepared.exists {
		receipt.PreparedReceiptID = loaded.prepared.state.identity
	}
	if _, err := persistAtomicTransformV2Receipt(stateDir, loaded.base, receipt, atomicTransformV2Complete); err != nil {
		return err
	}
	return nil
}

func retireAtomicTransformV2Receipts(loaded atomicTransformV2Loaded) error {
	targetDir, stateDir, err := bindAtomicTransformV2ReceiptDirectories(loaded.receipt)
	if err != nil {
		return err
	}
	defer targetDir.Close()
	defer stateDir.Close()
	// Rc moves first into its deterministic transaction-bound GC sentinel.
	// From this durable transition onward the loader enters cleanup-only mode
	// and can never re-enter live-target recovery, even if any later deletion is
	// interrupted.
	if !loaded.complete.retired {
		if !loaded.complete.exists {
			return fmt.Errorf("complete receipt is neither primary nor cleanup sentinel")
		}
		gcState, err := atomicTransformBoundRenameNoReplace(
			stateDir,
			filepath.Base(loaded.complete.path),
			filepath.Base(loaded.complete.gcPath),
			loaded.complete.state,
		)
		if err != nil {
			return fmt.Errorf("publish complete-receipt cleanup sentinel: %w", err)
		}
		loaded.complete.state = gcState
		loaded.complete.exists = false
		loaded.complete.retired = true
		loaded.gcOnly = true
		if err := runAtomicTransformPhaseHook(
			loaded.receipt.LogicalPath, atomicTransformPhaseCompleteRetired,
			atomicTransformV2HookState(loaded.base, loaded.receipt),
		); err != nil {
			return err
		}
	}
	if err := cleanupAtomicTransformV2MarkerSlots(targetDir, loaded.receipt); err != nil {
		return err
	}
	for _, phase := range []struct {
		receipt *atomicTransformV2PhaseReceipt
		hook    atomicTransformPhase
	}{
		{&loaded.allocation, atomicTransformPhaseAllocationRetired},
		{&loaded.staging, atomicTransformPhaseStagingRetired},
		{&loaded.prepared, atomicTransformPhasePreparedRetired},
		{&loaded.terminal, atomicTransformPhaseTerminalRetired},
	} {
		if !phase.receipt.located {
			continue
		}
		if err := stateDir.validatePrivate(); err != nil {
			return err
		}
		name := filepath.Base(phase.receipt.path)
		if phase.receipt.retired {
			name = filepath.Base(phase.receipt.gcPath)
		}
		current, err := atomicTransformBoundInspectPrivate(stateDir, name, atomicTransformMaxIntentBytes)
		if err != nil {
			return err
		}
		if current.exists {
			if !atomicTransformArtifactStatesEqualExact(current, phase.receipt.state) {
				return fmt.Errorf("compare-and-swap receipt changed before cleanup-only deletion: %s", name)
			}
			if err := atomicTransformBoundDeleteExact(stateDir, name, current); err != nil {
				return fmt.Errorf("delete exact cleanup-only receipt %s: %w", name, err)
			}
		}
		if err := runAtomicTransformPhaseHook(
			loaded.receipt.LogicalPath, phase.hook, atomicTransformV2HookState(loaded.base, loaded.receipt),
		); err != nil {
			return err
		}
	}
	// The exact Rc sentinel is the final deletion. Its absence proves that every
	// transaction-owned marker and earlier receipt was already cleaned.
	rcName := filepath.Base(loaded.complete.gcPath)
	rcState, err := atomicTransformBoundInspectPrivate(stateDir, rcName, atomicTransformMaxIntentBytes)
	if err != nil {
		return err
	}
	if !rcState.exists || !atomicTransformArtifactStatesEqualExact(rcState, loaded.complete.state) {
		return fmt.Errorf("complete cleanup sentinel changed before final deletion: %s", rcName)
	}
	if err := atomicTransformBoundDeleteExact(stateDir, rcName, rcState); err != nil {
		return fmt.Errorf("delete final complete cleanup sentinel: %w", err)
	}
	return nil
}

func cleanupAtomicTransformV2MarkerSlots(
	targetDir *atomicTransformBoundDirectory, receipt atomicTransformV2Receipt,
) error {
	type allowedArtifact struct {
		artifact   atomicTransformV2Artifact
		contents   bool
		stageKnown bool
	}
	type markerSlot struct {
		name    string
		max     int64
		allowed []allowedArtifact
	}
	slots := []markerSlot{
		{receipt.TerminalMarker.Name, atomicTransformMaxIntentBytes, []allowedArtifact{{artifact: receipt.TerminalMarker, contents: true}}},
		{receipt.TerminalMarkerName, atomicTransformMaxIntentBytes, []allowedArtifact{{artifact: receipt.TerminalMarker, contents: true}}},
	}
	if !receipt.Remove {
		slots = append(slots,
			markerSlot{receipt.StageMarker.Name, atomicTransformMaxIntentBytes, []allowedArtifact{{artifact: receipt.StageMarker, contents: true}}},
			// Rs can be interrupted with the exact held stage empty, partial, or
			// fully written. Identity/protection/mode—not plaintext bytes—binds
			// this provisional slot to the transaction.
			markerSlot{receipt.Stage.Name, atomicTransformMaxConfigBytes, []allowedArtifact{
				{artifact: receipt.StageMarker, contents: true},
				{artifact: receipt.Stage, contents: false, stageKnown: true},
			}},
			markerSlot{receipt.FinalMarker.Name, atomicTransformMaxIntentBytes, []allowedArtifact{{artifact: receipt.FinalMarker, contents: true}}},
			// A crash after Stage->StageFinal but before Rp leaves exact full New
			// here while Rs is still the only receipt.
			markerSlot{receipt.StageFinalName, atomicTransformMaxConfigBytes, []allowedArtifact{
				{artifact: receipt.FinalMarker, contents: true},
				{artifact: receipt.Stage, contents: true, stageKnown: true},
			}},
		)
	}
	seen := map[string]bool{}
	for _, slot := range slots {
		if slot.name == "" {
			continue
		}
		key := strings.ToLower(slot.name)
		if runtime.GOOS != "windows" {
			key = slot.name
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		state, err := atomicTransformBoundInspectFilePrivate(targetDir, slot.name, slot.max)
		if err != nil {
			return err
		}
		if !state.exists {
			continue
		}
		owned := false
		for _, allowed := range slot.allowed {
			if (allowed.stageKnown && atomicTransformV2KnownStageState(receipt, state)) ||
				atomicTransformV2StateMatches(allowed.artifact, state, allowed.contents) ||
				(allowed.contents && atomicTransformV2RenamedArtifactMatches(allowed.artifact, state)) {
				owned = true
				break
			}
		}
		if !owned {
			return fmt.Errorf("foreign object occupies completed compare-and-swap marker slot: %s", slot.name)
		}
		if err := atomicTransformBoundDeleteExact(targetDir, slot.name, state); err != nil {
			return err
		}
		if err := runAtomicTransformPhaseHook(
			receipt.LogicalPath, atomicTransformPhaseMarkerRetired,
			atomicTransformV2HookState(atomicTransformV2ReceiptPathForReceipt(receipt), receipt),
		); err != nil {
			return err
		}
	}
	return nil
}
