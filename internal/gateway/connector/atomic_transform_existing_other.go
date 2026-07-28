// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// conditionalCommitAtomicTransformExisting persists a recovery intent before
// it removes the target name. POSIX has no expected-inode rename primitive, so
// the inode moved to the tombstone is verified after the no-replace move. A
// raced replacement is restored and retried; two competing foreign files are
// retained with the intent for explicit recovery rather than losing either.
func conditionalCommitAtomicTransformExisting(
	path string,
	stateDir string,
	snapshot atomicFileSnapshot,
	stagedPath string,
	expectedStagedState atomicTransformArtifactState,
	remove bool,
) error {
	intent, intentPath, err := prepareAtomicTransformIntent(path, stateDir, snapshot, stagedPath, expectedStagedState, remove)
	if err != nil {
		if stagedPath != "" {
			_ = os.Remove(stagedPath)
		}
		return err
	}
	intentState, err := persistAtomicTransformIntent(intentPath, intent)
	if err != nil {
		if stagedPath != "" {
			_ = os.Remove(stagedPath)
		}
		return err
	}
	tombstone, staged := atomicTransformIntentArtifacts(intent)
	phaseState := atomicTransformPhaseState{
		IntentPath: intentPath,
		TargetPath: intent.TargetPath,
		Tombstone:  tombstone,
		Staged:     staged,
	}
	if err := runAtomicTransformPhaseHook(path, atomicTransformPhaseIntentPersisted, phaseState); err != nil {
		return err
	}

	resolved, err := resolveAtomicWritePath(path)
	if err == nil {
		resolved, err = canonicalAtomicTransformTargetPath(resolved)
	}
	if err != nil || !atomicTransformPathsEqual(resolved, intent.TargetPath) {
		return recoverAfterAtomicTransformError(path, stateDir, errAtomicTransformConflict)
	}
	if err := moveAtomicTransformPathNoReplace(intent.TargetPath, tombstone); err != nil {
		if errors.Is(err, errAtomicTransformConflict) || errors.Is(err, os.ErrNotExist) {
			return recoverAfterAtomicTransformError(path, stateDir, errAtomicTransformConflict)
		}
		return recoverAfterAtomicTransformError(path, stateDir, fmt.Errorf("move compared config to tombstone: %w", err))
	}
	if err := syncAtomicTransformParent(filepath.Dir(intent.TargetPath)); err != nil {
		return recoverAfterAtomicTransformError(path, stateDir, err)
	}
	matches, err := atomicTransformSnapshotMatchesPath(tombstone, snapshot)
	if err != nil {
		return recoverAfterAtomicTransformError(path, stateDir, err)
	}
	resolved, resolveErr := resolveAtomicWritePath(path)
	if resolveErr == nil {
		resolved, resolveErr = canonicalAtomicTransformTargetPath(resolved)
	}
	if !matches || resolveErr != nil || !atomicTransformPathsEqual(resolved, intent.TargetPath) {
		return recoverAfterAtomicTransformError(path, stateDir, errAtomicTransformConflict)
	}
	if err := runAtomicTransformPhaseHook(path, atomicTransformPhaseDetached, phaseState); err != nil {
		return err
	}

	if !remove {
		stagedState, inspectErr := inspectAtomicTransformArtifact(staged)
		if inspectErr != nil || !atomicTransformStateMatchesNew(stagedState, intent) {
			if inspectErr == nil {
				inspectErr = fmt.Errorf("staged config changed before publication")
			}
			return recoverAfterAtomicTransformError(path, stateDir, inspectErr)
		}
		if err := publishAtomicTransformArtifact(staged, intent.TargetPath, stagedState); err != nil {
			if errors.Is(err, errAtomicTransformConflict) {
				return recoverAfterAtomicTransformError(path, stateDir, errAtomicTransformConflict)
			}
			return recoverAfterAtomicTransformError(path, stateDir, fmt.Errorf("publish staged config: %w", err))
		}
		if err := syncAtomicTransformParent(filepath.Dir(intent.TargetPath)); err != nil {
			return recoverAfterAtomicTransformError(path, stateDir, err)
		}
	}
	if err := runAtomicTransformPhaseHook(path, atomicTransformPhasePublished, phaseState); err != nil {
		return err
	}
	return finishAtomicTransformIntent(intent, intentPath, intentState)
}

func openAtomicTransformRegularFile(path string) (*os.File, os.FileInfo, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("compare-and-swap artifact is not a regular non-link file: %s", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if !info.Mode().IsRegular() || !os.SameFile(pathInfo, info) {
		_ = file.Close()
		return nil, nil, fmt.Errorf("compare-and-swap artifact changed while opening: %s", path)
	}
	return file, info, nil
}

func atomicTransformSnapshotMatchesPath(path string, snapshot atomicFileSnapshot) (bool, error) {
	file, info, err := openAtomicTransformRegularFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	defer file.Close()
	identity, identityErr := atomicTransformOpenFileIdentity(file)
	if identityErr != nil {
		return false, identityErr
	}
	if !os.SameFile(snapshot.info, info) || identity != snapshot.identity || info.Mode() != snapshot.info.Mode() {
		return false, nil
	}
	data, err := readAtomicTransformBytes(file, path, atomicTransformMaxConfigBytes)
	if err != nil {
		return false, err
	}
	protectionDigest, err := atomicTransformProtectionDigest(file)
	if err != nil || protectionDigest != snapshot.protectionDigest {
		return false, err
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return pathInfo.Mode()&os.ModeSymlink == 0 && os.SameFile(info, pathInfo) && bytes.Equal(data, snapshot.data), nil
}

func publishAtomicTransformArtifact(source, target string, expected atomicTransformArtifactState) error {
	state, err := inspectAtomicTransformArtifact(source)
	if err != nil {
		return err
	}
	if !state.exists || !os.SameFile(state.info, expected.info) ||
		state.digest != expected.digest || state.size != expected.size || state.info.Mode() != expected.info.Mode() {
		return fmt.Errorf("staged compare-and-swap artifact changed before publication: %s", source)
	}
	if err := moveAtomicTransformPathNoReplace(source, target); err != nil {
		return err
	}
	published, err := inspectAtomicTransformArtifact(target)
	if err != nil {
		return err
	}
	if !published.exists || !os.SameFile(published.info, expected.info) ||
		published.digest != expected.digest || published.size != expected.size || published.info.Mode() != expected.info.Mode() {
		return fmt.Errorf("published compare-and-swap artifact has unexpected identity or contents: %s", target)
	}
	return nil
}

func restoreAtomicTransformArtifact(source, target string, expected atomicTransformArtifactState) error {
	state, err := inspectAtomicTransformArtifact(source)
	if err != nil {
		return err
	}
	if !state.exists || !os.SameFile(state.info, expected.info) ||
		state.digest != expected.digest || state.size != expected.size || state.info.Mode() != expected.info.Mode() {
		return fmt.Errorf("recovery tombstone changed before restore: %s", source)
	}
	if err := moveAtomicTransformPathNoReplace(source, target); err != nil {
		return err
	}
	restored, err := inspectAtomicTransformArtifact(target)
	if err != nil {
		return err
	}
	if !restored.exists || !os.SameFile(restored.info, expected.info) ||
		restored.digest != expected.digest || restored.size != expected.size || restored.info.Mode() != expected.info.Mode() {
		return fmt.Errorf("restored config has unexpected identity or contents: %s", target)
	}
	return nil
}

func atomicTransformProtectionDigest(*os.File) (string, error) {
	return "", nil
}

func syncAtomicTransformPlatformParent(dir string) error {
	parent, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open config parent for sync: %w", err)
	}
	syncErr := parent.Sync()
	closeErr := parent.Close()
	if syncErr != nil {
		return fmt.Errorf("sync config parent: %w", syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close config parent after sync: %w", closeErr)
	}
	return nil
}

// POSIX has no unlink-by-open-file-description operation. These names are
// constrained DefenseClaw-owned random artifacts, never the operator's live
// config path. Validate identity, bytes, and mode immediately before unlink;
// importantly, do not rename them to an unrecorded quarantine, because a crash
// there would make recovery lose the durable artifact name.
func deleteAtomicTransformArtifact(path string, expected atomicTransformArtifactState) error {
	state, err := inspectAtomicTransformArtifact(path)
	if err != nil {
		return err
	}
	if !state.exists || !os.SameFile(state.info, expected.info) ||
		state.digest != expected.digest || state.size != expected.size || state.info.Mode() != expected.info.Mode() {
		return fmt.Errorf("artifact changed before conditional deletion")
	}
	return os.Remove(path)
}
