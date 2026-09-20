// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// atomicTransformFileLegacy preserves the currently shipped caller path while
// the stable-state V2 API is being reviewed. Production callers must migrate
// explicitly with their protected opts.DataDir; they must never inherit a
// target-local V2 recovery namespace through this compatibility shim.
func atomicTransformFileLegacy(
	path string,
	perm os.FileMode,
	transform func(current []byte, exists bool) (atomicTransformResult, error),
) error {
	logical, err := canonicalAtomicTransformTargetPath(path)
	if err != nil {
		return err
	}
	stateDir, err := prepareAtomicTransformStateDir(
		filepath.Join(filepath.Dir(logical), ".defenseclaw-cas-state"),
	)
	if err != nil {
		return err
	}
	return atomicTransformFileLegacyPrepared(path, stateDir, perm, transform)
}

// atomicTransformFileLegacyWithStateDir retains the V1 engine on platforms
// without the Windows handle-bound namespace primitives while honoring the
// caller's protected stable transaction directory. This preserves the public
// stable-state contract without compiling the Windows-only V2 protocol into a
// POSIX build.
func atomicTransformFileLegacyWithStateDir(
	path string,
	transactionDir string,
	perm os.FileMode,
	transform func(current []byte, exists bool) (atomicTransformResult, error),
) error {
	stateDir, err := prepareAtomicTransformStateDir(transactionDir)
	if err != nil {
		return err
	}
	return atomicTransformFileLegacyPrepared(path, stateDir, perm, transform)
}

func atomicTransformFileLegacyPrepared(
	path string,
	stateDir string,
	perm os.FileMode,
	transform func(current []byte, exists bool) (atomicTransformResult, error),
) error {
	for attempt := 0; attempt < atomicTransformMaxAttempts; attempt++ {
		if err := recoverAtomicTransformWithStateDirPrepared(path, stateDir); err != nil {
			return fmt.Errorf("recover interrupted config transform for %s: %w", path, err)
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
		semanticNoop := (!snapshot.exists && result.Remove) ||
			(snapshot.exists && !result.Remove && bytes.Equal(snapshot.data, result.Data) &&
				atomicTransformSnapshotSatisfiesPermissions(snapshot, writePerm))
		var stagedPath string
		var stagedState atomicTransformArtifactState
		if !result.Remove && !semanticNoop {
			stagedPath, stagedState, err = stageAtomicTransformFile(snapshot.writePath, result.Data, writePerm)
			if err != nil {
				return err
			}
		}
		runAtomicTransformBeforeCompareHook(path, attempt)
		matches, err := atomicFileSnapshotStillMatches(path, snapshot)
		if err != nil || !matches {
			if stagedPath != "" {
				if cleanupErr := removeExpectedAtomicTransformArtifact(stagedPath, stagedState); cleanupErr != nil {
					return errors.Join(err, cleanupErr)
				}
			}
			if err != nil {
				return err
			}
			continue
		}
		if semanticNoop {
			return nil
		}
		runAtomicTransformBeforeCommitHook(path, attempt)
		if !snapshot.exists {
			if err := publishAtomicTransformArtifact(stagedPath, snapshot.writePath, stagedState); err != nil {
				_ = removeExpectedAtomicTransformArtifact(stagedPath, stagedState)
				if errors.Is(err, errAtomicTransformConflict) {
					continue
				}
				return err
			}
		} else if err := conditionalCommitAtomicTransformExisting(
			path, stateDir, snapshot, stagedPath, stagedState, result.Remove,
		); err != nil {
			if errors.Is(err, errAtomicTransformConflict) {
				continue
			}
			return err
		}
		if err := syncAtomicTransformParent(filepath.Dir(snapshot.writePath)); err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf(
		"config %s changed during each of %d read/merge attempts; refusing to overwrite concurrent edits",
		path, atomicTransformMaxAttempts,
	)
}
