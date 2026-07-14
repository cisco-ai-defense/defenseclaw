// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

const (
	atomicTransformMaxAttempts         = 8
	atomicTransformIntentVersion       = 1
	atomicTransformMaxIntentBytes      = 64 << 10
	atomicTransformMaxConfigBytes      = 32 << 20
	atomicTransformMaxIntentCandidates = 64
	atomicTransformIntentPrepared      = "prepared"
	atomicTransformIntentComplete      = "complete"
)

var errAtomicTransformConflict = errors.New("atomic transform target changed")

// atomicTransformResult is the next state returned by a read/merge
// transformation. Remove is used by teardown when the connector originally
// created a config file that did not exist before setup.
type atomicTransformResult struct {
	Data   []byte
	Remove bool
	Perm   os.FileMode
}

type atomicFileSnapshot struct {
	writePath                string
	exists                   bool
	data                     []byte
	info                     os.FileInfo
	identity                 string
	parentIdentity           string
	protectionDigest         string
	metadataDigest           string
	preservedMetadataDigest  string
	stageOwnedMetadataDigest string
	ownerGroupDigest         string
	creationTime             uint64
	lastWriteTime            uint64
	linkCount                uint32
}

type atomicTransformIntent struct {
	Version             int    `json:"version"`
	Phase               string `json:"phase"`
	LogicalPath         string `json:"logical_path"`
	StateDir            string `json:"state_dir"`
	TargetPath          string `json:"target_path"`
	TombstoneName       string `json:"tombstone_name"`
	StagedName          string `json:"staged_name,omitempty"`
	Remove              bool   `json:"remove"`
	OldSHA256           string `json:"old_sha256"`
	NewSHA256           string `json:"new_sha256,omitempty"`
	OldSize             int64  `json:"old_size"`
	NewSize             int64  `json:"new_size,omitempty"`
	OldMode             uint32 `json:"old_mode"`
	OldIdentity         string `json:"old_identity,omitempty"`
	OldProtectionSHA256 string `json:"old_protection_sha256,omitempty"`
	NewMode             uint32 `json:"new_mode,omitempty"`
	NewProtectionSHA256 string `json:"new_protection_sha256,omitempty"`
}

type atomicTransformArtifactState struct {
	exists                   bool
	data                     []byte
	info                     os.FileInfo
	digest                   string
	size                     int64
	protectionDigest         string
	identity                 string
	metadataDigest           string
	preservedMetadataDigest  string
	stageOwnedMetadataDigest string
	ownerGroupDigest         string
	creationTime             uint64
	lastWriteTime            uint64
	linkCount                uint32
}

type atomicTransformPlatformMetadata struct {
	digest           string
	preservedDigest  string
	stageOwnedDigest string
	ownerGroupDigest string
	creationTime     uint64
	lastWriteTime    uint64
}

type atomicTransformLoadedIntent struct {
	intent        atomicTransformIntent
	logical       string
	path          string
	preparedState atomicTransformArtifactState
	completeState atomicTransformArtifactState
	exists        bool
}

type atomicTransformPhase string

const (
	atomicTransformPhaseStagingLocated            atomicTransformPhase = "staging-located"
	atomicTransformPhaseStagePartial              atomicTransformPhase = "stage-partially-written"
	atomicTransformPhaseStageFinalized            atomicTransformPhase = "stage-finalized"
	atomicTransformPhasePreReceiptArtifact        atomicTransformPhase = "pre-receipt-artifact-created"
	atomicTransformPhaseAllocationPersisted       atomicTransformPhase = "allocation-persisted"
	atomicTransformPhaseAllocationBootstrap       atomicTransformPhase = "allocation-bootstrap-progress"
	atomicTransformPhaseStagingBootstrap          atomicTransformPhase = "staging-receipt-bootstrap-progress"
	atomicTransformPhasePreparedBootstrap         atomicTransformPhase = "prepared-receipt-bootstrap-progress"
	atomicTransformPhaseTerminalBootstrap         atomicTransformPhase = "terminal-receipt-bootstrap-progress"
	atomicTransformPhaseCompleteBootstrap         atomicTransformPhase = "complete-receipt-bootstrap-progress"
	atomicTransformPhaseTerminalMarkerBootstrap   atomicTransformPhase = "terminal-marker-bootstrap-progress"
	atomicTransformPhasePayloadMarkerBootstrap    atomicTransformPhase = "payload-marker-bootstrap-progress"
	atomicTransformPhaseStageMarkerBootstrap      atomicTransformPhase = "stage-marker-bootstrap-progress"
	atomicTransformPhaseReadyMarkerBootstrap      atomicTransformPhase = "ready-marker-bootstrap-progress"
	atomicTransformPhaseIntentPersisted           atomicTransformPhase = "intent-persisted"
	atomicTransformPhaseDetached                  atomicTransformPhase = "detached"
	atomicTransformPhasePublished                 atomicTransformPhase = "published"
	atomicTransformPhaseFinalPublicationValidated atomicTransformPhase = "final-publication-validated"
	atomicTransformPhaseCleanupStarted            atomicTransformPhase = "cleanup-started"
	atomicTransformPhaseCompleted                 atomicTransformPhase = "completed"
	atomicTransformPhaseCompletionValidated       atomicTransformPhase = "completion-validated"
	atomicTransformPhaseTerminalWitnessed         atomicTransformPhase = "terminal-witnessed"
	atomicTransformPhaseMarkerEstablished         atomicTransformPhase = "marker-established"
	atomicTransformPhaseMarkerRetired             atomicTransformPhase = "marker-retired"
	atomicTransformPhaseReceiptCleanup            atomicTransformPhase = "receipt-cleanup"
	atomicTransformPhaseStagingRetired            atomicTransformPhase = "staging-retired"
	atomicTransformPhaseAllocationRetired         atomicTransformPhase = "allocation-retired"
	atomicTransformPhasePreparedRetired           atomicTransformPhase = "prepared-retired"
	atomicTransformPhaseTerminalRetired           atomicTransformPhase = "terminal-retired"
	atomicTransformPhaseCompleteRetired           atomicTransformPhase = "complete-retired"
)

type atomicTransformPhaseState struct {
	IntentPath        string
	ReceiptPath       string
	TargetPath        string
	Tombstone         string
	Staged            string
	StagedProvisional string
	StagedFinal       string
	TerminalMarker    string
}

// atomicTransformFile performs an optimistic read/merge/compare-and-swap.
//
// The advisory connector lock serializes DefenseClaw processes, but Codex,
// Claude Code, an editor, or an enterprise policy agent can update the same
// config without taking that lock. Each attempt therefore reads an exact file
// snapshot, reruns the complete caller-supplied transformation, stages the
// replacement, and then verifies the target's file identity and bytes
// immediately before replacement. A changed snapshot is never overwritten;
// it causes a fresh read/merge attempt. Persistent contention fails closed.
// atomicTransformFile remains temporarily for local CAS tests while production
// callers migrate to atomicTransformFileWithStateDir. It must not be used by
// connector code because a directory reached through a retargetable alias is
// not a stable recovery namespace.
func atomicTransformFile(
	path string,
	perm os.FileMode,
	transform func(current []byte, exists bool) (atomicTransformResult, error),
) error {
	return atomicTransformFileLegacy(path, perm, transform)
}

func atomicTransformSnapshotSatisfiesPermissions(snapshot atomicFileSnapshot, requested os.FileMode) bool {
	if runtime.GOOS == "windows" && requested.Perm()&0o077 == 0 {
		if err := safefile.ValidatePrivateFile(snapshot.writePath); err != nil {
			return false
		}
		writable := snapshot.info.Mode().Perm()&0o222 != 0
		return writable == (requested.Perm()&0o200 != 0)
	}
	return snapshot.info.Mode().Perm() == requested.Perm()
}

func loadManagedFileBackupForTransform(
	dataDir, connectorName, logicalName, targetPath string,
) (*managedFileBackup, error) {
	backup, err := loadManagedFileBackupPath(managedFileBackupPath(dataDir, connectorName, logicalName))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if _, err := validateManagedFileBackupTarget(backup, connectorName, logicalName, targetPath); err != nil {
		return nil, err
	}
	return &backup, nil
}

// managedFileBackupTransform returns the exact pristine state only when the
// bytes being transformed still match the connector's recorded post-setup
// state. A drifted file falls through to the caller's surgical merge.
func managedFileBackupTransform(
	backup *managedFileBackup,
	current []byte,
	exists bool,
) (atomicTransformResult, bool) {
	if backup == nil {
		return atomicTransformResult{}, false
	}
	if !managedFileBackupMatchesSnapshot(backup, current, exists) {
		return atomicTransformResult{}, false
	}
	if !backup.Existed {
		return atomicTransformResult{Remove: true}, true
	}
	mode := os.FileMode(backup.Mode)
	if mode == 0 {
		mode = 0o600
	}
	return atomicTransformResult{
		Data: append([]byte(nil), backup.PristineBytes...),
		Perm: mode,
	}, true
}

func readAtomicFileSnapshot(path string) (atomicFileSnapshot, error) {
	for attempt := 0; attempt < atomicTransformMaxAttempts; attempt++ {
		writePath, err := resolveAtomicWritePath(path)
		if err != nil {
			return atomicFileSnapshot{}, err
		}
		writePath, err = canonicalAtomicTransformTargetPath(writePath)
		if err != nil {
			return atomicFileSnapshot{}, err
		}
		parentIdentity, parentErr := atomicTransformDirectoryIdentity(filepath.Dir(writePath))
		if parentErr != nil && !errors.Is(parentErr, os.ErrNotExist) {
			return atomicFileSnapshot{}, fmt.Errorf("identify config parent %s: %w", filepath.Dir(writePath), parentErr)
		}
		snapshot := atomicFileSnapshot{writePath: writePath, parentIdentity: parentIdentity}
		file, err := os.Open(writePath)
		if err != nil {
			if os.IsNotExist(err) {
				return snapshot, nil
			}
			return snapshot, fmt.Errorf("open %s for compare-and-swap: %w", writePath, err)
		}

		info, statErr := file.Stat()
		if statErr != nil {
			_ = file.Close()
			return snapshot, fmt.Errorf("stat open config %s: %w", writePath, statErr)
		}
		if !info.Mode().IsRegular() {
			_ = file.Close()
			return snapshot, fmt.Errorf("config %s is not a regular file", writePath)
		}
		data, readErr := readAtomicTransformBytes(file, writePath, atomicTransformMaxConfigBytes)
		identity, identityErr := atomicTransformOpenFileIdentity(file)
		protectionDigest, protectionErr := atomicTransformProtectionDigest(file)
		metadata, metadataErr := atomicTransformMetadataPlatform(file)
		linkCount, linkCountErr := atomicTransformBoundLinkCountPlatform(file)
		closeErr := file.Close()
		if readErr != nil {
			return snapshot, fmt.Errorf("read open config %s: %w", writePath, readErr)
		}
		if closeErr != nil {
			return snapshot, fmt.Errorf("close open config %s: %w", writePath, closeErr)
		}
		if protectionErr != nil {
			return snapshot, fmt.Errorf("inspect open config protection %s: %w", writePath, protectionErr)
		}
		if metadataErr != nil {
			return snapshot, fmt.Errorf("inspect open config metadata %s: %w", writePath, metadataErr)
		}
		if linkCountErr != nil {
			return snapshot, fmt.Errorf("inspect open config hard-link count %s: %w", writePath, linkCountErr)
		}
		if runtime.GOOS == "windows" && linkCount != 1 {
			return snapshot, fmt.Errorf("Windows config %s has %d hard links; refusing ambiguous replacement", writePath, linkCount)
		}
		if identityErr != nil {
			return snapshot, fmt.Errorf("identify open config %s: %w", writePath, identityErr)
		}
		pathInfo, lstatErr := os.Lstat(writePath)
		if lstatErr != nil {
			if os.IsNotExist(lstatErr) {
				continue
			}
			return snapshot, fmt.Errorf("lstat config %s after read: %w", writePath, lstatErr)
		}
		if pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, pathInfo) {
			continue
		}
		snapshot.exists = true
		snapshot.data = data
		snapshot.info = info
		snapshot.identity = identity
		snapshot.protectionDigest = protectionDigest
		snapshot.metadataDigest = metadata.digest
		snapshot.preservedMetadataDigest = metadata.preservedDigest
		snapshot.stageOwnedMetadataDigest = metadata.stageOwnedDigest
		snapshot.ownerGroupDigest = metadata.ownerGroupDigest
		snapshot.creationTime = metadata.creationTime
		snapshot.lastWriteTime = metadata.lastWriteTime
		snapshot.linkCount = linkCount
		return snapshot, nil
	}
	return atomicFileSnapshot{}, fmt.Errorf(
		"%w: config %s did not remain stable during %d snapshot attempts",
		errAtomicTransformConflict,
		path,
		atomicTransformMaxAttempts,
	)
}

func atomicFileSnapshotStillMatches(path string, snapshot atomicFileSnapshot) (bool, error) {
	writePath, err := resolveAtomicWritePath(path)
	if err != nil {
		return false, err
	}
	writePath, err = canonicalAtomicTransformTargetPath(writePath)
	if err != nil {
		return false, err
	}
	if !atomicTransformPathsEqual(writePath, snapshot.writePath) {
		return false, nil
	}
	if snapshot.parentIdentity != "" {
		parent, bindErr := bindAtomicTransformDirectory(filepath.Dir(writePath))
		if bindErr != nil {
			return false, bindErr
		}
		parentMatches := parent.identity == snapshot.parentIdentity
		closeErr := parent.Close()
		if closeErr != nil {
			return false, closeErr
		}
		if !parentMatches {
			return false, nil
		}
	}
	if !snapshot.exists {
		_, err := os.Lstat(writePath)
		if os.IsNotExist(err) {
			return true, nil
		}
		if err != nil {
			return false, fmt.Errorf("lstat config %s before create: %w", writePath, err)
		}
		return false, nil
	}

	file, err := os.Open(writePath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("open config %s before replacement: %w", writePath, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return false, fmt.Errorf("stat config %s before replacement: %w", writePath, err)
	}
	identity, err := atomicTransformOpenFileIdentity(file)
	if err != nil {
		return false, fmt.Errorf("identify config %s before replacement: %w", writePath, err)
	}
	if !os.SameFile(snapshot.info, info) || identity != snapshot.identity {
		return false, nil
	}
	if snapshot.info.Mode() != info.Mode() {
		return false, nil
	}
	data, err := readAtomicTransformBytes(file, writePath, atomicTransformMaxConfigBytes)
	if err != nil {
		return false, fmt.Errorf("read config %s before replacement: %w", writePath, err)
	}
	if !bytes.Equal(snapshot.data, data) {
		return false, nil
	}
	protectionDigest, err := atomicTransformProtectionDigest(file)
	if err != nil {
		return false, fmt.Errorf("inspect config protection %s before replacement: %w", writePath, err)
	}
	if protectionDigest != snapshot.protectionDigest {
		return false, nil
	}
	metadata, err := atomicTransformMetadataPlatform(file)
	if err != nil {
		return false, fmt.Errorf("inspect config metadata %s before replacement: %w", writePath, err)
	}
	if metadata.digest != snapshot.metadataDigest ||
		metadata.preservedDigest != snapshot.preservedMetadataDigest ||
		metadata.stageOwnedDigest != snapshot.stageOwnedMetadataDigest ||
		metadata.ownerGroupDigest != snapshot.ownerGroupDigest ||
		metadata.creationTime != snapshot.creationTime ||
		metadata.lastWriteTime != snapshot.lastWriteTime {
		return false, nil
	}
	linkCount, err := atomicTransformBoundLinkCountPlatform(file)
	if err != nil {
		return false, fmt.Errorf("inspect config hard-link count %s before replacement: %w", writePath, err)
	}
	if linkCount != snapshot.linkCount {
		return false, nil
	}
	pathInfo, err := os.Lstat(writePath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("lstat config %s before replacement: %w", writePath, err)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, pathInfo) {
		return false, nil
	}
	resolvedAgain, err := resolveAtomicWritePath(path)
	if err != nil {
		return false, err
	}
	resolvedAgain, err = canonicalAtomicTransformTargetPath(resolvedAgain)
	if err != nil {
		return false, err
	}
	return atomicTransformPathsEqual(resolvedAgain, snapshot.writePath), nil
}

func stageAtomicTransformFile(
	writePath string,
	data []byte,
	perm os.FileMode,
) (string, atomicTransformArtifactState, error) {
	dir := filepath.Dir(writePath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", atomicTransformArtifactState{}, fmt.Errorf("create directory for %s: %w", writePath, err)
	}
	tmp, err := os.CreateTemp(dir, ".tmp-cas-provisional-*")
	if err != nil {
		return "", atomicTransformArtifactState{}, fmt.Errorf("create compare-and-swap temp file: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func(cause error) (string, atomicTransformArtifactState, error) {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return "", atomicTransformArtifactState{}, cause
	}
	if runtime.GOOS == "windows" && perm.Perm()&0o077 == 0 {
		if err := safefile.ProtectFile(tmpPath); err != nil {
			return cleanup(fmt.Errorf("protect compare-and-swap temp file: %w", err))
		}
	}
	if _, err := tmp.Write(data); err != nil {
		return cleanup(fmt.Errorf("write compare-and-swap temp file: %w", err))
	}
	if err := tmp.Chmod(perm); err != nil {
		return cleanup(fmt.Errorf("chmod compare-and-swap temp file: %w", err))
	}
	if err := tmp.Sync(); err != nil {
		return cleanup(fmt.Errorf("sync compare-and-swap temp file: %w", err))
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return "", atomicTransformArtifactState{}, fmt.Errorf("close compare-and-swap temp file: %w", err)
	}
	provisionalState, err := inspectAtomicTransformArtifact(tmpPath)
	if err != nil || !provisionalState.exists {
		_ = os.Remove(tmpPath)
		if err == nil {
			err = fmt.Errorf("provisional compare-and-swap stage disappeared")
		}
		return "", atomicTransformArtifactState{}, fmt.Errorf("inspect provisional compare-and-swap stage: %w", err)
	}

	// File.Sync makes the bytes durable, but does not establish a durable name.
	// Publish the final random stage name through the platform's no-replace
	// namespace primitive before any prepared intent can refer to it. Windows
	// uses MoveFileEx(MOVEFILE_WRITE_THROUGH); POSIX follows the link publication
	// with a parent-directory fsync.
	for attempt := 0; attempt < atomicTransformMaxAttempts; attempt++ {
		placeholder, err := os.CreateTemp(dir, ".tmp-cas-*")
		if err != nil {
			_ = os.Remove(tmpPath)
			return "", atomicTransformArtifactState{}, fmt.Errorf("reserve durable compare-and-swap stage name: %w", err)
		}
		finalPath := placeholder.Name()
		if err := placeholder.Close(); err != nil {
			_ = os.Remove(finalPath)
			_ = os.Remove(tmpPath)
			return "", atomicTransformArtifactState{}, fmt.Errorf("close durable compare-and-swap stage reservation: %w", err)
		}
		if err := os.Remove(finalPath); err != nil {
			_ = os.Remove(tmpPath)
			return "", atomicTransformArtifactState{}, fmt.Errorf("release durable compare-and-swap stage reservation: %w", err)
		}
		if err := installAtomicTransformFile(tmpPath, finalPath); err != nil {
			if errors.Is(err, errAtomicTransformConflict) {
				continue
			}
			_ = os.Remove(tmpPath)
			return "", atomicTransformArtifactState{}, fmt.Errorf("publish durable compare-and-swap stage name: %w", err)
		}
		if err := syncAtomicTransformParent(dir); err != nil {
			_ = os.Remove(finalPath)
			return "", atomicTransformArtifactState{}, fmt.Errorf("sync durable compare-and-swap stage name: %w", err)
		}
		finalState, err := inspectAtomicTransformArtifact(finalPath)
		if err != nil || !finalState.exists || !os.SameFile(finalState.info, provisionalState.info) ||
			finalState.digest != provisionalState.digest || finalState.size != provisionalState.size ||
			finalState.info.Mode() != provisionalState.info.Mode() ||
			finalState.protectionDigest != provisionalState.protectionDigest {
			_ = os.Remove(finalPath)
			if err == nil {
				err = fmt.Errorf("durably published stage changed identity or metadata")
			}
			return "", atomicTransformArtifactState{}, fmt.Errorf("verify durable compare-and-swap stage name: %w", err)
		}
		return finalPath, finalState, nil
	}
	_ = os.Remove(tmpPath)
	return "", atomicTransformArtifactState{}, fmt.Errorf("could not reserve a unique durable compare-and-swap stage name after %d attempts", atomicTransformMaxAttempts)
}

func atomicTransformTombstonePath(writePath, stagedPath string) (string, error) {
	if stagedPath != "" {
		candidate := stagedPath + ".previous"
		if _, err := os.Lstat(candidate); os.IsNotExist(err) {
			return candidate, nil
		} else if err != nil {
			return "", err
		}
		return "", fmt.Errorf("compare-and-swap tombstone already exists: %s", candidate)
	}
	placeholder, err := os.CreateTemp(filepath.Dir(writePath), ".tmp-cas-previous-*")
	if err != nil {
		return "", fmt.Errorf("reserve compare-and-swap tombstone: %w", err)
	}
	path := placeholder.Name()
	if err := placeholder.Close(); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("close compare-and-swap tombstone placeholder: %w", err)
	}
	if err := os.Remove(path); err != nil {
		return "", fmt.Errorf("release compare-and-swap tombstone placeholder: %w", err)
	}
	return path, nil
}

func canonicalAtomicTransformPath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("make compare-and-swap path absolute: %w", err)
	}
	return filepath.Clean(absolute), nil
}

func canonicalAtomicTransformTargetPath(path string) (string, error) {
	absolute, err := canonicalAtomicTransformPath(path)
	if err != nil {
		return "", err
	}
	leaf := filepath.Base(absolute)
	parent := filepath.Dir(absolute)
	missing := make([]string, 0, 4)
	for {
		resolved, evalErr := atomicTransformResolveDirectoryPathPlatform(parent)
		if evalErr == nil {
			for index := len(missing) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, missing[index])
			}
			candidate, canonicalErr := canonicalAtomicTransformPath(filepath.Join(resolved, leaf))
			if canonicalErr != nil {
				return "", canonicalErr
			}
			return atomicTransformCanonicalizeExistingLeafPlatform(candidate)
		}
		if !errors.Is(evalErr, os.ErrNotExist) {
			return "", fmt.Errorf("resolve compare-and-swap target parent %s: %w", parent, evalErr)
		}
		next := filepath.Dir(parent)
		if next == parent {
			return "", fmt.Errorf("resolve compare-and-swap target parent %s: %w", parent, evalErr)
		}
		missing = append(missing, filepath.Base(parent))
		parent = next
	}
}

func prepareAtomicTransformStateDir(path string) (string, error) {
	stateDir, err := canonicalAtomicTransformPath(path)
	if err != nil {
		return "", err
	}
	if err := safefile.ProtectDirectory(stateDir); err != nil {
		return "", err
	}
	if err := safefile.ValidatePrivateDirectory(stateDir); err != nil {
		return "", err
	}
	if err := atomicTransformValidateDirectoryCaseSemantics(stateDir); err != nil {
		return "", err
	}
	return stateDir, nil
}

func atomicTransformDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func readAtomicTransformBytes(file *os.File, path string, maxBytes int64) ([]byte, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %s before bounded read: %w", path, err)
	}
	if info.Size() > maxBytes {
		return nil, fmt.Errorf("compare-and-swap artifact exceeds %d-byte limit: %s", maxBytes, path)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("compare-and-swap artifact exceeds %d-byte limit: %s", maxBytes, path)
	}
	return data, nil
}

func atomicTransformIntentPathInStateDir(path, stateDir string) (string, string, error) {
	logical, err := canonicalAtomicTransformPath(path)
	if err != nil {
		return "", "", err
	}
	stateDir, err = canonicalAtomicTransformPath(stateDir)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256([]byte(logical))
	name := fmt.Sprintf(".defenseclaw-cas-%x.intent", sum[:12])
	return logical, filepath.Join(stateDir, name), nil
}

func atomicTransformIntentPath(path string) (string, string, error) {
	logical, err := canonicalAtomicTransformPath(path)
	if err != nil {
		return "", "", err
	}
	physical, err := canonicalAtomicTransformTargetPath(logical)
	if err != nil {
		return "", "", err
	}
	return atomicTransformIntentPathInStateDir(logical, filepath.Join(filepath.Dir(physical), ".defenseclaw-cas-state"))
}

func atomicTransformCompleteReceiptPath(intentPath string) string {
	return intentPath + ".complete"
}

func prepareAtomicTransformIntent(
	path string,
	stateDir string,
	snapshot atomicFileSnapshot,
	stagedPath string,
	expectedStagedState atomicTransformArtifactState,
	remove bool,
) (atomicTransformIntent, string, error) {
	logical, intentPath, err := atomicTransformIntentPathInStateDir(path, stateDir)
	if err != nil {
		return atomicTransformIntent{}, "", err
	}
	target, err := canonicalAtomicTransformTargetPath(snapshot.writePath)
	if err != nil {
		return atomicTransformIntent{}, "", err
	}
	tombstone, err := atomicTransformTombstonePath(target, stagedPath)
	if err != nil {
		return atomicTransformIntent{}, "", err
	}
	tombstone, err = canonicalAtomicTransformPath(tombstone)
	if err != nil {
		return atomicTransformIntent{}, "", err
	}
	if !atomicTransformPathsEqual(filepath.Dir(tombstone), filepath.Dir(target)) {
		return atomicTransformIntent{}, "", fmt.Errorf("compare-and-swap tombstone escaped target directory")
	}
	oldState, err := inspectAtomicTransformArtifact(target)
	if err != nil {
		return atomicTransformIntent{}, "", fmt.Errorf("inspect compared config before intent publication: %w", err)
	}
	if !oldState.exists || !os.SameFile(snapshot.info, oldState.info) ||
		oldState.identity != snapshot.identity ||
		oldState.digest != atomicTransformDigest(snapshot.data) || oldState.info.Mode() != snapshot.info.Mode() ||
		oldState.protectionDigest != snapshot.protectionDigest {
		return atomicTransformIntent{}, "", errAtomicTransformConflict
	}

	intent := atomicTransformIntent{
		Version:             atomicTransformIntentVersion,
		Phase:               atomicTransformIntentPrepared,
		LogicalPath:         logical,
		StateDir:            stateDir,
		TargetPath:          target,
		TombstoneName:       filepath.Base(tombstone),
		Remove:              remove,
		OldSHA256:           atomicTransformDigest(snapshot.data),
		OldSize:             int64(len(snapshot.data)),
		OldMode:             uint32(snapshot.info.Mode()),
		OldIdentity:         oldState.identity,
		OldProtectionSHA256: oldState.protectionDigest,
	}
	if stagedPath != "" {
		staged, err := canonicalAtomicTransformPath(stagedPath)
		if err != nil {
			return atomicTransformIntent{}, "", err
		}
		if !atomicTransformPathsEqual(filepath.Dir(staged), filepath.Dir(target)) {
			return atomicTransformIntent{}, "", fmt.Errorf("compare-and-swap staged file escaped target directory")
		}
		state, err := inspectAtomicTransformArtifact(staged)
		if err != nil {
			return atomicTransformIntent{}, "", fmt.Errorf("inspect staged config: %w", err)
		}
		if !state.exists || !expectedStagedState.exists || !os.SameFile(state.info, expectedStagedState.info) ||
			state.digest != expectedStagedState.digest || state.size != expectedStagedState.size ||
			state.info.Mode() != expectedStagedState.info.Mode() ||
			state.protectionDigest != expectedStagedState.protectionDigest {
			return atomicTransformIntent{}, "", fmt.Errorf("staged config changed before intent publication")
		}
		intent.StagedName = filepath.Base(staged)
		intent.NewSHA256 = state.digest
		intent.NewSize = state.size
		intent.NewMode = uint32(state.info.Mode())
		intent.NewProtectionSHA256 = state.protectionDigest
	}
	if err := validateAtomicTransformIntent(intent, logical, intentPath); err != nil {
		return atomicTransformIntent{}, "", err
	}
	return intent, intentPath, nil
}

func marshalAtomicTransformIntent(intent atomicTransformIntent) ([]byte, error) {
	body, err := json.Marshal(intent)
	if err != nil {
		return nil, fmt.Errorf("marshal compare-and-swap recovery intent: %w", err)
	}
	return append(body, '\n'), nil
}

func persistAtomicTransformIntent(
	intentPath string,
	intent atomicTransformIntent,
) (atomicTransformArtifactState, error) {
	if _, err := os.Lstat(intentPath); err == nil {
		return atomicTransformArtifactState{}, fmt.Errorf("compare-and-swap recovery intent already exists: %s", intentPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return atomicTransformArtifactState{}, fmt.Errorf("inspect compare-and-swap recovery intent: %w", err)
	}
	body, err := marshalAtomicTransformIntent(intent)
	if err != nil {
		return atomicTransformArtifactState{}, err
	}
	tmp, stagedState, err := stageAtomicTransformFile(intentPath, body, 0o600)
	if err != nil {
		return atomicTransformArtifactState{}, err
	}
	if err := installAtomicTransformFile(tmp, intentPath); err != nil {
		_ = os.Remove(tmp)
		if errors.Is(err, errAtomicTransformConflict) {
			return atomicTransformArtifactState{}, fmt.Errorf("compare-and-swap recovery intent appeared concurrently: %s", intentPath)
		}
		return atomicTransformArtifactState{}, fmt.Errorf("publish compare-and-swap recovery intent: %w", err)
	}
	if err := syncAtomicTransformParent(filepath.Dir(intentPath)); err != nil {
		return atomicTransformArtifactState{}, fmt.Errorf("sync compare-and-swap recovery intent: %w", err)
	}
	state, err := inspectAtomicTransformArtifactBounded(intentPath, atomicTransformMaxIntentBytes)
	if err != nil || !state.exists || !os.SameFile(state.info, stagedState.info) ||
		state.digest != stagedState.digest || state.size != stagedState.size ||
		state.info.Mode() != stagedState.info.Mode() ||
		state.protectionDigest != stagedState.protectionDigest {
		if err == nil {
			err = fmt.Errorf("published prepared intent changed identity or metadata")
		}
		return atomicTransformArtifactState{}, fmt.Errorf("verify published compare-and-swap recovery intent: %w", err)
	}
	return state, nil
}

func completeAtomicTransformIntent(
	intentPath string,
	intent atomicTransformIntent,
	expected atomicTransformArtifactState,
) (atomicTransformIntent, error) {
	current, err := inspectAtomicTransformArtifactBounded(intentPath, atomicTransformMaxIntentBytes)
	if err != nil {
		return atomicTransformIntent{}, err
	}
	if !current.exists || !os.SameFile(current.info, expected.info) ||
		current.digest != expected.digest || current.size != expected.size ||
		current.info.Mode() != expected.info.Mode() ||
		current.protectionDigest != expected.protectionDigest {
		return atomicTransformIntent{}, fmt.Errorf("prepared compare-and-swap intent changed before completion: %s", intentPath)
	}
	tombstone, staged := atomicTransformIntentArtifacts(intent)
	if err := runAtomicTransformPhaseHook(intent.LogicalPath, atomicTransformPhaseCompletionValidated, atomicTransformPhaseState{
		IntentPath: intentPath,
		TargetPath: intent.TargetPath,
		Tombstone:  tombstone,
		Staged:     staged,
	}); err != nil {
		return atomicTransformIntent{}, err
	}
	intent.Phase = atomicTransformIntentComplete
	body, err := marshalAtomicTransformIntent(intent)
	if err != nil {
		return atomicTransformIntent{}, err
	}
	completePath := atomicTransformCompleteReceiptPath(intentPath)
	tmp, sentinelState, err := stageAtomicTransformFile(completePath, body, 0o600)
	if err != nil {
		return atomicTransformIntent{}, err
	}
	// Reoccupying the exact tombstone slot through a write-through no-replace
	// publication is the durable Windows proof that the old config deletion can
	// no longer roll back after all receipts vanish. The second write-through
	// move consumes that slot and publishes the terminal receipt.
	if err := publishAtomicTransformArtifact(tmp, tombstone, sentinelState); err != nil {
		_ = os.Remove(tmp)
		return atomicTransformIntent{}, fmt.Errorf("durably witness tombstone cleanup in its namespace slot: %w", err)
	}
	if err := syncAtomicTransformParent(filepath.Dir(tombstone)); err != nil {
		return atomicTransformIntent{}, err
	}
	tombstoneState, err := inspectAtomicTransformArtifactBounded(tombstone, atomicTransformMaxIntentBytes)
	if err != nil {
		return atomicTransformIntent{}, err
	}
	if !atomicTransformArtifactStatesEqualExact(tombstoneState, sentinelState) {
		return atomicTransformIntent{}, fmt.Errorf("terminal completion sentinel did not persist exactly: %s", tombstone)
	}
	if err := runAtomicTransformPhaseHook(intent.LogicalPath, atomicTransformPhaseTerminalWitnessed, atomicTransformPhaseState{
		IntentPath: intentPath,
		TargetPath: intent.TargetPath,
		Tombstone:  tombstone,
		Staged:     staged,
	}); err != nil {
		return atomicTransformIntent{}, err
	}
	if err := publishAtomicTransformArtifact(tombstone, completePath, tombstoneState); err != nil {
		return atomicTransformIntent{}, fmt.Errorf("durably publish no-replace completed compare-and-swap receipt: %w", err)
	}
	if err := syncAtomicTransformIntentParents(intent, intentPath); err != nil {
		return atomicTransformIntent{}, err
	}
	state, err := inspectAtomicTransformArtifactBounded(completePath, atomicTransformMaxIntentBytes)
	if err != nil {
		return atomicTransformIntent{}, err
	}
	if !atomicTransformArtifactStatesEqualExact(state, sentinelState) ||
		state.digest != atomicTransformDigest(body) {
		return atomicTransformIntent{}, fmt.Errorf("completed compare-and-swap receipt did not persist exactly: %s", completePath)
	}
	current, err = inspectAtomicTransformArtifactBounded(intentPath, atomicTransformMaxIntentBytes)
	if err != nil {
		return atomicTransformIntent{}, err
	}
	if !atomicTransformArtifactStatesEqualExact(current, expected) {
		return atomicTransformIntent{}, fmt.Errorf(
			"prepared compare-and-swap intent changed while publishing completion receipt; retained both artifacts",
		)
	}
	return intent, nil
}

func validateAtomicTransformIntent(intent atomicTransformIntent, logical, intentPath string) error {
	if intent.Version != atomicTransformIntentVersion {
		return fmt.Errorf("unsupported compare-and-swap recovery intent version %d", intent.Version)
	}
	if intent.Phase != atomicTransformIntentPrepared && intent.Phase != atomicTransformIntentComplete {
		return fmt.Errorf("unsupported compare-and-swap recovery intent phase %q", intent.Phase)
	}
	storedLogical, err := canonicalAtomicTransformPath(intent.LogicalPath)
	if err != nil || !atomicTransformLocationsEquivalent(storedLogical, logical) {
		return fmt.Errorf("compare-and-swap recovery intent belongs to a different logical path")
	}
	storedStateDir, err := canonicalAtomicTransformPath(intent.StateDir)
	if err != nil || !atomicTransformLocationsEquivalent(storedStateDir, filepath.Dir(intentPath)) {
		return fmt.Errorf("compare-and-swap recovery intent belongs to a different stable state directory")
	}
	_, expectedIntentPath, err := atomicTransformIntentPathInStateDir(storedLogical, storedStateDir)
	if err != nil ||
		!atomicTransformPathsEqual(filepath.Base(expectedIntentPath), filepath.Base(intentPath)) ||
		!atomicTransformLocationsEquivalent(expectedIntentPath, intentPath) {
		return fmt.Errorf("compare-and-swap recovery intent path does not match its owner")
	}
	target, err := canonicalAtomicTransformPath(intent.TargetPath)
	if err != nil || !filepath.IsAbs(target) || !atomicTransformPathsEqual(target, intent.TargetPath) {
		return fmt.Errorf("compare-and-swap recovery target is not canonical")
	}
	validateName := func(label, name string, required bool) error {
		if name == "" {
			if required {
				return fmt.Errorf("compare-and-swap recovery intent has no %s", label)
			}
			return nil
		}
		if filepath.Base(name) != name || name == "." || name == ".." {
			return fmt.Errorf("compare-and-swap recovery %s is not a constrained artifact name", label)
		}
		return nil
	}
	if err := validateName("tombstone", intent.TombstoneName, true); err != nil {
		return err
	}
	if err := validateName("staged file", intent.StagedName, !intent.Remove); err != nil {
		return err
	}
	if intent.Remove && intent.StagedName != "" {
		return fmt.Errorf("remove recovery intent unexpectedly contains a staged file")
	}
	if intent.TombstoneName == intent.StagedName {
		return fmt.Errorf("compare-and-swap recovery artifacts overlap")
	}
	if intent.Remove {
		if !atomicTransformGeneratedTempName(intent.TombstoneName, ".tmp-cas-previous-", "") {
			return fmt.Errorf("remove recovery tombstone does not match the generated name pattern")
		}
	} else {
		if !atomicTransformGeneratedTempName(intent.StagedName, ".tmp-cas-", "") {
			return fmt.Errorf("replacement recovery staged file does not match the generated name pattern")
		}
		if intent.TombstoneName != intent.StagedName+".previous" {
			return fmt.Errorf("replacement recovery tombstone is not bound to its staged artifact")
		}
	}
	validateDigest := func(label, digest string, required bool) error {
		if digest == "" && !required {
			return nil
		}
		decoded, err := hex.DecodeString(digest)
		if err != nil || len(decoded) != sha256.Size || digest != strings.ToLower(digest) {
			return fmt.Errorf("compare-and-swap recovery %s is invalid", label)
		}
		return nil
	}
	if err := validateDigest("old digest", intent.OldSHA256, true); err != nil {
		return err
	}
	if err := validateDigest("new digest", intent.NewSHA256, !intent.Remove); err != nil {
		return err
	}
	if intent.OldSize < 0 || intent.OldSize > atomicTransformMaxConfigBytes {
		return fmt.Errorf("compare-and-swap recovery old size is out of bounds")
	}
	if intent.NewSize < 0 || intent.NewSize > atomicTransformMaxConfigBytes {
		return fmt.Errorf("compare-and-swap recovery new size is out of bounds")
	}
	if intent.Remove && intent.NewSize != 0 {
		return fmt.Errorf("remove recovery intent unexpectedly contains a new-file size")
	}
	if os.FileMode(intent.OldMode)&os.ModeType != 0 {
		return fmt.Errorf("compare-and-swap recovery old mode is not regular")
	}
	if len(intent.OldIdentity) > 256 || strings.IndexFunc(intent.OldIdentity, func(r rune) bool {
		return r < 0x20 || r == 0x7f
	}) >= 0 {
		return fmt.Errorf("compare-and-swap recovery old identity is invalid")
	}
	if err := validateDigest("old protection digest", intent.OldProtectionSHA256, runtime.GOOS == "windows"); err != nil {
		return err
	}
	if err := validateDigest("new protection digest", intent.NewProtectionSHA256, !intent.Remove && runtime.GOOS == "windows"); err != nil {
		return err
	}
	if !intent.Remove && os.FileMode(intent.NewMode)&os.ModeType != 0 {
		return fmt.Errorf("compare-and-swap recovery new mode is not regular")
	}
	if intent.Remove && (intent.NewMode != 0 || intent.NewProtectionSHA256 != "") {
		return fmt.Errorf("remove recovery intent unexpectedly contains new-file metadata")
	}
	return nil
}

func atomicTransformGeneratedTempName(name, prefix, suffix string) bool {
	if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, suffix) {
		return false
	}
	middle := strings.TrimSuffix(strings.TrimPrefix(name, prefix), suffix)
	if middle == "" {
		return false
	}
	for _, char := range middle {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

func parseAtomicTransformIntentState(
	state atomicTransformArtifactState,
	sourcePath string,
) (atomicTransformIntent, error) {
	decoder := json.NewDecoder(bytes.NewReader(state.data))
	decoder.DisallowUnknownFields()
	var intent atomicTransformIntent
	if err := decoder.Decode(&intent); err != nil {
		return atomicTransformIntent{}, fmt.Errorf("parse compare-and-swap recovery intent %s: %w", sourcePath, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return atomicTransformIntent{}, fmt.Errorf("compare-and-swap recovery intent has trailing content: %s", sourcePath)
	}
	return intent, nil
}

func decodeAtomicTransformIntentState(
	state atomicTransformArtifactState,
	logical, intentPath, sourcePath string,
) (atomicTransformIntent, error) {
	intent, err := parseAtomicTransformIntentState(state, sourcePath)
	if err != nil {
		return atomicTransformIntent{}, err
	}
	if err := validateAtomicTransformIntent(intent, logical, intentPath); err != nil {
		return atomicTransformIntent{}, fmt.Errorf("validate compare-and-swap recovery intent %s: %w", sourcePath, err)
	}
	return intent, nil
}

func loadAtomicTransformIntentAt(
	logical, intentPath string,
) (atomicTransformLoadedIntent, error) {
	loaded := atomicTransformLoadedIntent{logical: logical, path: intentPath}
	state, err := inspectAtomicTransformArtifactBounded(intentPath, atomicTransformMaxIntentBytes)
	if err != nil {
		return loaded, fmt.Errorf("read compare-and-swap recovery intent: %w", err)
	}
	loaded.preparedState = state
	completePath := atomicTransformCompleteReceiptPath(intentPath)
	completeState, completeErr := inspectAtomicTransformArtifactBounded(completePath, atomicTransformMaxIntentBytes)
	if completeErr != nil {
		loaded.exists = state.exists
		return loaded, fmt.Errorf("read completed compare-and-swap receipt: %w", completeErr)
	}
	loaded.completeState = completeState
	if !state.exists && !completeState.exists {
		return loaded, nil
	}
	loaded.exists = true
	if !state.exists {
		intent, err := decodeAtomicTransformIntentState(completeState, logical, intentPath, completePath)
		if err != nil || intent.Phase != atomicTransformIntentComplete {
			if err == nil {
				err = fmt.Errorf("standalone completion receipt is not complete")
			}
			return loaded, err
		}
		loaded.intent = intent
		return loaded, nil
	}
	intent, err := decodeAtomicTransformIntentState(state, logical, intentPath, intentPath)
	if err != nil {
		return loaded, err
	}
	if !completeState.exists {
		loaded.intent = intent
		return loaded, nil
	}
	completed, err := decodeAtomicTransformIntentState(completeState, logical, intentPath, completePath)
	if err != nil {
		return loaded, err
	}
	if completed.Phase != atomicTransformIntentComplete {
		return loaded, fmt.Errorf("completion witness is not complete: %s", completePath)
	}
	prepared := completed
	prepared.Phase = atomicTransformIntentPrepared
	preparedBytes, err := marshalAtomicTransformIntent(prepared)
	if err != nil {
		return loaded, err
	}
	if state.digest != atomicTransformDigest(preparedBytes) {
		return loaded, fmt.Errorf("prepared intent and completion witness do not describe the same transaction")
	}
	loaded.intent = completed
	return loaded, nil
}

func loadAtomicTransformIntentAtOwned(
	intentPath string,
) (atomicTransformLoadedIntent, error) {
	loaded := atomicTransformLoadedIntent{path: intentPath}
	state, err := inspectAtomicTransformArtifactBounded(intentPath, atomicTransformMaxIntentBytes)
	if err != nil {
		return loaded, err
	}
	loaded.preparedState = state
	completePath := atomicTransformCompleteReceiptPath(intentPath)
	completeState, err := inspectAtomicTransformArtifactBounded(completePath, atomicTransformMaxIntentBytes)
	if err != nil {
		loaded.exists = state.exists
		return loaded, err
	}
	loaded.completeState = completeState
	if !state.exists && !completeState.exists {
		return loaded, nil
	}
	loaded.exists = true
	sourceState := state
	sourcePath := intentPath
	if !sourceState.exists {
		sourceState = completeState
		sourcePath = completePath
	}
	parsed, err := parseAtomicTransformIntentState(sourceState, sourcePath)
	if err != nil {
		return loaded, err
	}
	ownerLogical, err := canonicalAtomicTransformPath(parsed.LogicalPath)
	if err != nil {
		return loaded, fmt.Errorf("canonicalize compare-and-swap receipt owner %s: %w", sourcePath, err)
	}
	return loadAtomicTransformIntentAt(ownerLogical, intentPath)
}

func atomicTransformIntentCandidateBase(name string) (string, bool) {
	base := name
	hasSuffix := strings.HasSuffix
	hasPrefix := strings.HasPrefix
	if runtime.GOOS == "windows" {
		hasSuffix = atomicTransformASCIIHasSuffix
		hasPrefix = atomicTransformASCIIHasPrefix
	}
	if hasSuffix(base, ".complete") {
		base = base[:len(base)-len(".complete")]
	}
	if !hasPrefix(base, ".defenseclaw-cas-") || !hasSuffix(base, ".intent") {
		return "", false
	}
	digest := base[len(".defenseclaw-cas-") : len(base)-len(".intent")]
	if len(digest) != 24 {
		return "", false
	}
	for _, char := range digest {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') ||
			(runtime.GOOS == "windows" && char >= 'A' && char <= 'F')) {
			return "", false
		}
	}
	return base, true
}

func atomicTransformASCIIHasPrefix(value, prefix string) bool {
	return len(value) >= len(prefix) && atomicTransformASCIIEqualFold(value[:len(prefix)], prefix)
}

func atomicTransformASCIIHasSuffix(value, suffix string) bool {
	return len(value) >= len(suffix) && atomicTransformASCIIEqualFold(value[len(value)-len(suffix):], suffix)
}

func atomicTransformASCIIEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		left := a[index]
		right := b[index]
		if left >= 'A' && left <= 'Z' {
			left += 'a' - 'A'
		}
		if right >= 'A' && right <= 'Z' {
			right += 'a' - 'A'
		}
		if left != right {
			return false
		}
	}
	return true
}

func loadAtomicTransformIntentWithStates(path, stateDir string) (atomicTransformLoadedIntent, error) {
	logical, primaryPath, err := atomicTransformIntentPathInStateDir(path, stateDir)
	if err != nil {
		return atomicTransformLoadedIntent{}, err
	}

	// Discover the bounded set of DefenseClaw receipts in the stable protected
	// transaction directory and validate each stored owner. This supports
	// physical directory aliases without trusting the operator-controlled config
	// parent as the recovery namespace.
	directory, err := os.Open(stateDir)
	if errors.Is(err, os.ErrNotExist) {
		return atomicTransformLoadedIntent{logical: logical, path: primaryPath}, nil
	}
	if err != nil {
		return atomicTransformLoadedIntent{}, fmt.Errorf("open stable directory for compare-and-swap recovery intent enumeration: %w", err)
	}
	defer directory.Close()
	candidatePaths := make([]string, 0, atomicTransformMaxIntentCandidates)
	for {
		entries, readErr := directory.ReadDir(32)
		for _, entry := range entries {
			base, ok := atomicTransformIntentCandidateBase(entry.Name())
			if !ok {
				continue
			}
			candidatePath := filepath.Join(stateDir, base)
			duplicate := false
			for _, existing := range candidatePaths {
				if atomicTransformPathsEqual(existing, candidatePath) {
					duplicate = true
					break
				}
			}
			if duplicate {
				continue
			}
			candidatePaths = append(candidatePaths, candidatePath)
			if len(candidatePaths) > atomicTransformMaxIntentCandidates {
				return atomicTransformLoadedIntent{}, fmt.Errorf(
					"compare-and-swap recovery intent candidate limit exceeded in %s",
					stateDir,
				)
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return atomicTransformLoadedIntent{}, fmt.Errorf("enumerate compare-and-swap recovery intents: %w", readErr)
		}
	}

	matched := atomicTransformLoadedIntent{logical: logical, path: primaryPath}
	for _, candidatePath := range candidatePaths {
		candidate, candidateErr := loadAtomicTransformIntentAtOwned(candidatePath)
		if candidateErr != nil {
			// A torn or malformed DefenseClaw-pattern receipt cannot prove which
			// ordinal-equal spelling it owns. Fail closed instead of letting a
			// caller bypass unresolved recovery merely by changing path casing.
			return candidate, candidateErr
		}
		if !candidate.exists {
			continue
		}
		if !atomicTransformLocationsEquivalent(candidate.logical, logical) {
			continue
		}
		if matched.exists {
			return atomicTransformLoadedIntent{}, fmt.Errorf(
				"multiple compare-and-swap recovery intents claim Windows path %s: %s and %s",
				logical,
				matched.path,
				candidatePath,
			)
		}
		matched = candidate
	}
	return matched, nil
}

func loadAtomicTransformIntent(path string) (atomicTransformIntent, string, atomicTransformArtifactState, bool, error) {
	logical, canonicalErr := canonicalAtomicTransformPath(path)
	if canonicalErr != nil {
		return atomicTransformIntent{}, "", atomicTransformArtifactState{}, false, canonicalErr
	}
	loaded, err := loadAtomicTransformIntentWithStates(
		path,
		filepath.Join(filepath.Dir(logical), ".defenseclaw-cas-state"),
	)
	return loaded.intent, loaded.path, loaded.preparedState, loaded.exists, err
}

func inspectAtomicTransformArtifact(path string) (atomicTransformArtifactState, error) {
	return inspectAtomicTransformArtifactBounded(path, atomicTransformMaxConfigBytes)
}

func inspectAtomicTransformArtifactBounded(path string, maxBytes int64) (atomicTransformArtifactState, error) {
	file, info, err := openAtomicTransformRegularFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return atomicTransformArtifactState{}, nil
		}
		return atomicTransformArtifactState{}, err
	}
	defer file.Close()
	data, err := readAtomicTransformBytes(file, path, maxBytes)
	if err != nil {
		return atomicTransformArtifactState{}, fmt.Errorf("read regular artifact %s: %w", path, err)
	}
	protectionDigest, err := atomicTransformProtectionDigest(file)
	if err != nil {
		return atomicTransformArtifactState{}, fmt.Errorf("inspect artifact protection %s: %w", path, err)
	}
	identity, err := atomicTransformOpenFileIdentity(file)
	if err != nil {
		return atomicTransformArtifactState{}, fmt.Errorf("inspect artifact identity %s: %w", path, err)
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return atomicTransformArtifactState{}, fmt.Errorf("artifact changed while reading: %s", path)
		}
		return atomicTransformArtifactState{}, err
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, pathInfo) {
		return atomicTransformArtifactState{}, fmt.Errorf("artifact changed identity while reading: %s", path)
	}
	return atomicTransformArtifactState{
		exists:           true,
		data:             data,
		info:             info,
		digest:           atomicTransformDigest(data),
		size:             int64(len(data)),
		protectionDigest: protectionDigest,
		identity:         identity,
	}, nil
}

func atomicTransformIntentArtifacts(intent atomicTransformIntent) (string, string) {
	dir := filepath.Dir(intent.TargetPath)
	tombstone := filepath.Join(dir, intent.TombstoneName)
	staged := ""
	if intent.StagedName != "" {
		staged = filepath.Join(dir, intent.StagedName)
	}
	return tombstone, staged
}

func removeExpectedAtomicTransformArtifact(
	path string,
	state atomicTransformArtifactState,
) error {
	if path == "" || !state.exists {
		return nil
	}
	if err := deleteAtomicTransformArtifact(path, state); err != nil {
		return fmt.Errorf("conditionally delete compare-and-swap artifact %s: %w", path, err)
	}
	return nil
}

func syncAtomicTransformIntentParents(intent atomicTransformIntent, intentPath string) error {
	if err := syncAtomicTransformParent(filepath.Dir(intent.TargetPath)); err != nil {
		return err
	}
	if !atomicTransformPathsEqual(filepath.Dir(intent.TargetPath), filepath.Dir(intentPath)) {
		if err := syncAtomicTransformParent(filepath.Dir(intentPath)); err != nil {
			return err
		}
	}
	return nil
}

func atomicTransformStateMatchesMetadata(
	state atomicTransformArtifactState,
	digest string,
	size int64,
	mode uint32,
	protectionDigest string,
) bool {
	return state.exists &&
		state.digest == digest &&
		state.size == size &&
		state.info.Mode() == os.FileMode(mode) &&
		state.protectionDigest == protectionDigest
}

func atomicTransformStateMatchesOld(
	state atomicTransformArtifactState,
	intent atomicTransformIntent,
) bool {
	return atomicTransformStateMatchesMetadata(
		state,
		intent.OldSHA256,
		intent.OldSize,
		intent.OldMode,
		intent.OldProtectionSHA256,
	)
}

func atomicTransformStateMatchesNew(
	state atomicTransformArtifactState,
	intent atomicTransformIntent,
) bool {
	return atomicTransformStateMatchesMetadata(
		state,
		intent.NewSHA256,
		intent.NewSize,
		intent.NewMode,
		intent.NewProtectionSHA256,
	)
}

func atomicTransformArtifactStatesEqualExact(a, b atomicTransformArtifactState) bool {
	if a.exists != b.exists {
		return false
	}
	if !a.exists {
		return true
	}
	return os.SameFile(a.info, b.info) &&
		a.identity == b.identity &&
		a.digest == b.digest &&
		a.size == b.size &&
		a.info.Mode() == b.info.Mode() &&
		a.protectionDigest == b.protectionDigest &&
		a.metadataDigest == b.metadataDigest &&
		a.preservedMetadataDigest == b.preservedMetadataDigest &&
		a.stageOwnedMetadataDigest == b.stageOwnedMetadataDigest &&
		a.ownerGroupDigest == b.ownerGroupDigest &&
		a.creationTime == b.creationTime &&
		a.lastWriteTime == b.lastWriteTime &&
		a.linkCount == b.linkCount
}

func atomicTransformStateMatchesCompletionSentinel(
	state atomicTransformArtifactState,
	intent atomicTransformIntent,
) bool {
	if !state.exists {
		return false
	}
	completed := intent
	completed.Phase = atomicTransformIntentComplete
	body, err := marshalAtomicTransformIntent(completed)
	return err == nil && state.size == int64(len(body)) && state.digest == atomicTransformDigest(body)
}

func atomicTransformLogicalTargetMatches(intent atomicTransformIntent) (bool, error) {
	resolved, err := resolveAtomicWritePath(intent.LogicalPath)
	if err == nil {
		resolved, err = canonicalAtomicTransformTargetPath(resolved)
	}
	if err != nil {
		return false, fmt.Errorf("resolve interrupted transform logical path: %w", err)
	}
	return atomicTransformPathsEqual(resolved, intent.TargetPath), nil
}

func cleanupAtomicTransformRecovery(
	intent atomicTransformIntent,
	intentPath string,
	intentState atomicTransformArtifactState,
	tombstone string,
	tombstoneState atomicTransformArtifactState,
	staged string,
	stagedState atomicTransformArtifactState,
) error {
	if err := removeExpectedAtomicTransformArtifact(tombstone, tombstoneState); err != nil {
		return err
	}
	if err := removeExpectedAtomicTransformArtifact(staged, stagedState); err != nil {
		return err
	}
	if err := syncAtomicTransformParent(filepath.Dir(intent.TargetPath)); err != nil {
		return err
	}
	if err := removeExpectedAtomicTransformArtifact(intentPath, intentState); err != nil {
		return err
	}
	return syncAtomicTransformIntentParents(intent, intentPath)
}

func recoverAtomicTransformOnce(path, stateDir string) error {
	loaded, err := loadAtomicTransformIntentWithStates(path, stateDir)
	if err != nil || !loaded.exists {
		return err
	}
	intent := loaded.intent
	intentPath := loaded.path
	intentState := loaded.preparedState
	targetMatches, err := atomicTransformLogicalTargetMatches(intent)
	if err != nil {
		return err
	}
	tombstone, staged := atomicTransformIntentArtifacts(intent)
	targetState, err := inspectAtomicTransformArtifact(intent.TargetPath)
	if err != nil {
		return fmt.Errorf("inspect interrupted transform target: %w", err)
	}
	tombstoneState, err := inspectAtomicTransformArtifact(tombstone)
	if err != nil {
		return fmt.Errorf("inspect interrupted transform tombstone: %w", err)
	}
	stagedState := atomicTransformArtifactState{}
	if staged != "" {
		stagedState, err = inspectAtomicTransformArtifact(staged)
		if err != nil {
			return fmt.Errorf("inspect interrupted transform staged file: %w", err)
		}
	}

	stagedMatches := !stagedState.exists || atomicTransformStateMatchesNew(stagedState, intent)
	tombstoneMatchesOld := !tombstoneState.exists || atomicTransformStateMatchesOld(tombstoneState, intent)
	if intent.Phase == atomicTransformIntentComplete {
		completePath := atomicTransformCompleteReceiptPath(intentPath)
		if !loaded.completeState.exists {
			return fmt.Errorf("completed transaction has no durable completion witness: %s", completePath)
		}
		if err := runAtomicTransformPhaseHook(intent.LogicalPath, atomicTransformPhaseReceiptCleanup, atomicTransformPhaseState{
			IntentPath: intentPath,
			TargetPath: intent.TargetPath,
			Tombstone:  tombstone,
			Staged:     staged,
		}); err != nil {
			return err
		}
		completeState, err := inspectAtomicTransformArtifactBounded(completePath, atomicTransformMaxIntentBytes)
		if err != nil {
			return err
		}
		if !atomicTransformArtifactStatesEqualExact(completeState, loaded.completeState) {
			return fmt.Errorf("completed compare-and-swap receipt changed identity before cleanup: %s", completePath)
		}
		if intentState.exists {
			currentIntentState, err := inspectAtomicTransformArtifactBounded(intentPath, atomicTransformMaxIntentBytes)
			if err != nil {
				return err
			}
			if !atomicTransformArtifactStatesEqualExact(currentIntentState, intentState) {
				return fmt.Errorf("prepared compare-and-swap intent changed identity before completed cleanup: %s", intentPath)
			}
		}
		tombstoneIsSentinel := atomicTransformStateMatchesCompletionSentinel(tombstoneState, intent)
		tombstoneIsExactOld := tombstoneState.exists && intent.OldIdentity != "" &&
			tombstoneState.identity == intent.OldIdentity &&
			tombstoneState.digest == intent.OldSHA256 &&
			tombstoneState.size == intent.OldSize &&
			tombstoneState.info.Mode() == os.FileMode(intent.OldMode)
		if (!tombstoneMatchesOld && !tombstoneIsExactOld && !tombstoneIsSentinel) || !stagedMatches {
			return fmt.Errorf(
				"completed compare-and-swap receipt has changed artifacts (prior_matches=%t [exact_identity=%t exists=%t digest=%t size=%t mode=%t protection=%t], terminal_matches=%t, stage_matches=%t); retaining %s",
				tombstoneMatchesOld,
				tombstoneIsExactOld,
				tombstoneState.exists,
				tombstoneState.digest == intent.OldSHA256,
				tombstoneState.size == intent.OldSize,
				tombstoneState.exists && tombstoneState.info.Mode() == os.FileMode(intent.OldMode),
				tombstoneState.protectionDigest == intent.OldProtectionSHA256,
				tombstoneIsSentinel, stagedMatches, intentPath,
			)
		}
		if !intent.Remove && !targetState.exists {
			return fmt.Errorf("completed replacement target is absent; retaining recovery receipt %s", intentPath)
		}
		// The complete receipt was published with MOVEFILE_WRITE_THROUGH after
		// live-state cleanup. A visible target is always authoritative; cleanup
		// only the receipt-owned random artifacts and the receipt itself.
		if err := removeExpectedAtomicTransformArtifact(tombstone, tombstoneState); err != nil {
			return err
		}
		if err := removeExpectedAtomicTransformArtifact(staged, stagedState); err != nil {
			return err
		}
		if err := syncAtomicTransformParent(filepath.Dir(intent.TargetPath)); err != nil {
			return err
		}
		// Remove the completion witness first. A crash here leaves the prepared
		// intent, whose filesystem matrix can safely infer/republish completion.
		if err := removeExpectedAtomicTransformArtifact(completePath, loaded.completeState); err != nil {
			return err
		}
		if err := removeExpectedAtomicTransformArtifact(intentPath, intentState); err != nil {
			return err
		}
		return syncAtomicTransformIntentParents(intent, intentPath)
	}
	if atomicTransformStateMatchesCompletionSentinel(tombstoneState, intent) {
		if stagedState.exists {
			return fmt.Errorf("terminal completion sentinel coexists with staged config; retaining recovery artifacts")
		}
		if !intent.Remove && !targetState.exists {
			return fmt.Errorf("terminal completion sentinel exists but replacement target is absent; retaining recovery artifacts")
		}
		if !intentState.exists {
			return fmt.Errorf("terminal completion sentinel has no prepared intent: %s", intentPath)
		}
		currentIntentState, err := inspectAtomicTransformArtifactBounded(intentPath, atomicTransformMaxIntentBytes)
		if err != nil {
			return err
		}
		if !atomicTransformArtifactStatesEqualExact(currentIntentState, intentState) {
			return fmt.Errorf("prepared intent changed while terminal completion sentinel was pending: %s", intentPath)
		}
		completePath := atomicTransformCompleteReceiptPath(intentPath)
		if err := publishAtomicTransformArtifact(tombstone, completePath, tombstoneState); err != nil {
			return fmt.Errorf("resume durable terminal completion publication: %w", err)
		}
		if err := syncAtomicTransformIntentParents(intent, intentPath); err != nil {
			return err
		}
		return runAtomicTransformPhaseHook(intent.LogicalPath, atomicTransformPhaseCompleted, atomicTransformPhaseState{
			IntentPath: intentPath,
			TargetPath: intent.TargetPath,
			Tombstone:  tombstone,
			Staged:     staged,
		})
	}
	if tombstoneState.exists && !tombstoneMatchesOld {
		// POSIX cannot bind the no-replace rename to the inode from the earlier
		// snapshot. If an editor wins immediately before detach, its exact file
		// object is moved to the tombstone. Restoring that inspected object while
		// target is absent is lossless, then the operation can retry. Windows
		// detaches through the already-compared handle and must reject a changed
		// recovery tombstone instead.
		if runtime.GOOS != "windows" && !targetState.exists &&
			stagedMatches && (intent.Remove || stagedState.exists) {
			if err := restoreAtomicTransformArtifact(tombstone, intent.TargetPath, tombstoneState); err != nil {
				return fmt.Errorf("restore POSIX file raced into recovery tombstone: %w", err)
			}
			if err := syncAtomicTransformParent(filepath.Dir(intent.TargetPath)); err != nil {
				return err
			}
			tombstoneState = atomicTransformArtifactState{}
			return cleanupAtomicTransformRecovery(
				intent, intentPath, intentState, tombstone, tombstoneState, staged, stagedState,
			)
		}
		return fmt.Errorf(
			"recovery tombstone does not match the recorded prior config metadata; retaining %s and %s",
			tombstone,
			intentPath,
		)
	}
	if !targetMatches {
		// A retarget before detach is recoverable without touching the old
		// target: discard only our random stage and intent, then let the caller
		// retry against the new logical destination. Once a tombstone exists,
		// retain everything because the old target may already be detached.
		if !tombstoneState.exists && atomicTransformStateMatchesOld(targetState, intent) &&
			stagedMatches {
			return cleanupAtomicTransformRecovery(
				intent, intentPath, intentState, tombstone, tombstoneState, staged, stagedState,
			)
		}
		if !intent.Remove && !stagedState.exists && atomicTransformStateMatchesNew(targetState, intent) {
			return finishAtomicTransformIntent(intent, intentPath, intentState)
		}
		if intent.Remove && !targetState.exists && !tombstoneState.exists {
			return finishAtomicTransformIntent(intent, intentPath, intentState)
		}
		return fmt.Errorf(
			"logical config no longer resolves to recovery target %s; retaining recovery artifacts",
			intent.TargetPath,
		)
	}
	if !stagedMatches {
		if tombstoneState.exists && !targetState.exists {
			if err := restoreAtomicTransformArtifact(tombstone, intent.TargetPath, tombstoneState); err != nil {
				return errors.Join(
					fmt.Errorf("changed staged artifact retained with recovery intent: %s", staged),
					fmt.Errorf("restore prior config while retaining changed stage: %w", err),
				)
			}
			if err := syncAtomicTransformParent(filepath.Dir(intent.TargetPath)); err != nil {
				return err
			}
		}
		return fmt.Errorf("changed staged artifact retained with recovery intent: %s", staged)
	}

	if intent.Remove {
		switch {
		case tombstoneState.exists && targetState.exists:
			return fmt.Errorf(
				"ambiguous interrupted removal retained current target %s, prior config %s, and intent %s",
				intent.TargetPath,
				tombstone,
				intentPath,
			)
		case tombstoneState.exists:
			if err := restoreAtomicTransformArtifact(tombstone, intent.TargetPath, tombstoneState); err != nil {
				return fmt.Errorf("restore prior config after interrupted removal: %w", err)
			}
			if err := syncAtomicTransformParent(filepath.Dir(intent.TargetPath)); err != nil {
				return err
			}
			tombstoneState = atomicTransformArtifactState{}
		}
		// No tombstone plus an absent target means exact tombstone deletion
		// committed the removal. Publish a durable completion witness before
		// clearing the prepared intent. A present target is authoritative and
		// means the operation can be safely aborted without touching it.
		if !targetState.exists {
			return finishAtomicTransformIntent(intent, intentPath, intentState)
		}
		return cleanupAtomicTransformRecovery(
			intent, intentPath, intentState, tombstone, tombstoneState, staged, stagedState,
		)
	}

	if stagedState.exists {
		// The staged name is the pre-publication witness: a successful
		// no-replace publish consumes it atomically.
		if tombstoneState.exists {
			if targetState.exists {
				return fmt.Errorf(
					"ambiguous pre-publication conflict retained target %s, prior config %s, staged config %s, and intent %s",
					intent.TargetPath,
					tombstone,
					staged,
					intentPath,
				)
			}
			if err := restoreAtomicTransformArtifact(tombstone, intent.TargetPath, tombstoneState); err != nil {
				return fmt.Errorf("restore prior config after interrupted replacement: %w", err)
			}
			if err := syncAtomicTransformParent(filepath.Dir(intent.TargetPath)); err != nil {
				return err
			}
			tombstoneState = atomicTransformArtifactState{}
		} else if !targetState.exists {
			return fmt.Errorf(
				"ambiguous interrupted replacement has neither target nor prior tombstone; retaining staged config %s and intent %s",
				staged,
				intentPath,
			)
		}
		return cleanupAtomicTransformRecovery(
			intent, intentPath, intentState, tombstone, tombstoneState, staged, stagedState,
		)
	}

	// A missing staged name proves a no-replace publication consumed that path,
	// but only the recorded new target metadata proves it was our staged object.
	// A foreign live target is ambiguous (operator edit after publication versus
	// stage-path substitution before publication), so preserve it and retain the
	// prior tombstone and prepared intent for explicit recovery.
	if !tombstoneState.exists && atomicTransformStateMatchesOld(targetState, intent) {
		return cleanupAtomicTransformRecovery(
			intent, intentPath, intentState, tombstone, tombstoneState, staged, stagedState,
		)
	}
	if !targetState.exists {
		return fmt.Errorf(
			"published staged name is gone but target is also absent; retaining prior tombstone %s and intent %s",
			tombstone,
			intentPath,
		)
	}
	if !atomicTransformStateMatchesNew(targetState, intent) {
		return fmt.Errorf(
			"published staged name is gone but target does not match the recorded new config; retaining target %s, prior tombstone %s, and intent %s",
			intent.TargetPath,
			tombstone,
			intentPath,
		)
	}
	return finishAtomicTransformIntent(intent, intentPath, intentState)
}

func recoverAtomicTransformWithStateDirPrepared(path, stateDir string) error {
	for pass := 0; pass < 3; pass++ {
		if err := recoverAtomicTransformOnce(path, stateDir); err != nil {
			return err
		}
	}
	loaded, err := loadAtomicTransformIntentWithStates(path, stateDir)
	if err != nil {
		return err
	}
	if loaded.exists {
		return fmt.Errorf("compare-and-swap recovery did not converge after bounded passes: %s", loaded.path)
	}
	return nil
}

func recoverAtomicTransformWithStateDir(path, transactionDir string) error {
	stateDir, err := prepareAtomicTransformStateDir(transactionDir)
	if err != nil {
		return err
	}
	return recoverAtomicTransformWithStateDirPrepared(path, stateDir)
}

func recoverAtomicTransform(path string) error {
	logical, err := canonicalAtomicTransformPath(path)
	if err != nil {
		return err
	}
	physical, err := canonicalAtomicTransformTargetPath(logical)
	if err != nil {
		return err
	}
	return recoverAtomicTransformWithStateDir(path, filepath.Join(filepath.Dir(physical), ".defenseclaw-cas-state"))
}

func finishAtomicTransformIntent(
	intent atomicTransformIntent,
	intentPath string,
	expectedIntentState atomicTransformArtifactState,
) error {
	tombstone, staged := atomicTransformIntentArtifacts(intent)
	intentState, err := inspectAtomicTransformArtifactBounded(intentPath, atomicTransformMaxIntentBytes)
	if err != nil {
		return fmt.Errorf("inspect recovery intent before cleanup %s: %w", intentPath, err)
	}
	if !intentState.exists {
		return fmt.Errorf("recovery intent disappeared before cleanup: %s", intentPath)
	}
	expectedIntent, err := marshalAtomicTransformIntent(intent)
	if err != nil {
		return err
	}
	if !os.SameFile(intentState.info, expectedIntentState.info) ||
		intentState.digest != atomicTransformDigest(expectedIntent) ||
		intentState.digest != expectedIntentState.digest ||
		intentState.size != expectedIntentState.size ||
		intentState.info.Mode() != expectedIntentState.info.Mode() ||
		intentState.protectionDigest != expectedIntentState.protectionDigest {
		return fmt.Errorf("recovery intent changed before cleanup: %s", intentPath)
	}
	tombstoneState, err := inspectAtomicTransformArtifact(tombstone)
	if err != nil {
		return err
	}
	if tombstoneState.exists && !atomicTransformStateMatchesOld(tombstoneState, intent) {
		return fmt.Errorf("tombstone changed before cleanup; retained recovery intent %s", intentPath)
	}
	stagedState := atomicTransformArtifactState{}
	if staged != "" {
		stagedState, err = inspectAtomicTransformArtifact(staged)
		if err != nil {
			return err
		}
		if stagedState.exists && !atomicTransformStateMatchesNew(stagedState, intent) {
			return fmt.Errorf("staged artifact changed before cleanup; retained recovery intent %s", intentPath)
		}
	}
	if err := removeExpectedAtomicTransformArtifact(tombstone, tombstoneState); err != nil {
		return err
	}
	if err := removeExpectedAtomicTransformArtifact(staged, stagedState); err != nil {
		return err
	}
	if err := syncAtomicTransformParent(filepath.Dir(intent.TargetPath)); err != nil {
		return err
	}
	if err := runAtomicTransformPhaseHook(intent.LogicalPath, atomicTransformPhaseCleanupStarted, atomicTransformPhaseState{
		IntentPath: intentPath,
		TargetPath: intent.TargetPath,
		Tombstone:  tombstone,
		Staged:     staged,
	}); err != nil {
		return err
	}
	_, err = completeAtomicTransformIntent(intentPath, intent, expectedIntentState)
	if err != nil {
		return err
	}
	if err := runAtomicTransformPhaseHook(intent.LogicalPath, atomicTransformPhaseCompleted, atomicTransformPhaseState{
		IntentPath: intentPath,
		TargetPath: intent.TargetPath,
		Tombstone:  tombstone,
		Staged:     staged,
	}); err != nil {
		return err
	}
	return nil
}

func recoverAfterAtomicTransformError(path, stateDir string, cause error) error {
	if err := recoverAtomicTransformWithStateDirPrepared(path, stateDir); err != nil {
		// Do not expose a recoverable conflict through errors.Is when recovery
		// itself found ambiguity. The outer retry loop would otherwise delete a
		// retained staged witness and retry over unresolved crash state.
		return fmt.Errorf("%v; recovery failed: %w", cause, err)
	}
	return cause
}

func syncAtomicTransformParent(dir string) error {
	return syncAtomicTransformPlatformParent(dir)
}

func atomicTransformPathsEqual(a, b string) bool {
	return atomicTransformPathsEqualPlatform(filepath.Clean(a), filepath.Clean(b))
}

func atomicTransformLocationsEquivalent(a, b string) bool {
	return atomicTransformLocationsEquivalentPlatform(filepath.Clean(a), filepath.Clean(b))
}

// A path-keyed injection seam makes concurrent-edit tests deterministic while
// allowing unrelated parallel package tests to continue safely.
var atomicTransformTestHooks = struct {
	sync.RWMutex
	byPath map[string]func(attempt int)
}{byPath: map[string]func(int){}}

var atomicTransformBeforeCommitTestHooks = struct {
	sync.RWMutex
	byPath map[string]func(attempt int)
}{byPath: map[string]func(int){}}

var atomicTransformPhaseTestHooks = struct {
	sync.RWMutex
	byPath map[string]func(atomicTransformPhase, atomicTransformPhaseState) error
}{byPath: map[string]func(atomicTransformPhase, atomicTransformPhaseState) error{}}

func setAtomicTransformBeforeCompareHookForTest(path string, hook func(attempt int)) func() {
	key := filepath.Clean(path)
	atomicTransformTestHooks.Lock()
	previous := atomicTransformTestHooks.byPath[key]
	atomicTransformTestHooks.byPath[key] = hook
	atomicTransformTestHooks.Unlock()
	return func() {
		atomicTransformTestHooks.Lock()
		defer atomicTransformTestHooks.Unlock()
		if previous == nil {
			delete(atomicTransformTestHooks.byPath, key)
			return
		}
		atomicTransformTestHooks.byPath[key] = previous
	}
}

func runAtomicTransformBeforeCompareHook(path string, attempt int) {
	key := filepath.Clean(path)
	atomicTransformTestHooks.RLock()
	hook := atomicTransformTestHooks.byPath[key]
	atomicTransformTestHooks.RUnlock()
	if hook != nil {
		hook(attempt)
	}
}

func setAtomicTransformBeforeCommitHookForTest(path string, hook func(attempt int)) func() {
	key := filepath.Clean(path)
	atomicTransformBeforeCommitTestHooks.Lock()
	previous := atomicTransformBeforeCommitTestHooks.byPath[key]
	atomicTransformBeforeCommitTestHooks.byPath[key] = hook
	atomicTransformBeforeCommitTestHooks.Unlock()
	return func() {
		atomicTransformBeforeCommitTestHooks.Lock()
		defer atomicTransformBeforeCommitTestHooks.Unlock()
		if previous == nil {
			delete(atomicTransformBeforeCommitTestHooks.byPath, key)
			return
		}
		atomicTransformBeforeCommitTestHooks.byPath[key] = previous
	}
}

func runAtomicTransformBeforeCommitHook(path string, attempt int) {
	key := filepath.Clean(path)
	atomicTransformBeforeCommitTestHooks.RLock()
	hook := atomicTransformBeforeCommitTestHooks.byPath[key]
	atomicTransformBeforeCommitTestHooks.RUnlock()
	if hook != nil {
		hook(attempt)
	}
}

func setAtomicTransformPhaseHookForTest(
	path string,
	hook func(atomicTransformPhase, atomicTransformPhaseState) error,
) func() {
	key := filepath.Clean(path)
	atomicTransformPhaseTestHooks.Lock()
	previous := atomicTransformPhaseTestHooks.byPath[key]
	atomicTransformPhaseTestHooks.byPath[key] = hook
	atomicTransformPhaseTestHooks.Unlock()
	return func() {
		atomicTransformPhaseTestHooks.Lock()
		defer atomicTransformPhaseTestHooks.Unlock()
		if previous == nil {
			delete(atomicTransformPhaseTestHooks.byPath, key)
			return
		}
		atomicTransformPhaseTestHooks.byPath[key] = previous
	}
}

func runAtomicTransformPhaseHook(
	path string,
	phase atomicTransformPhase,
	state atomicTransformPhaseState,
) error {
	key := filepath.Clean(path)
	atomicTransformPhaseTestHooks.RLock()
	hook := atomicTransformPhaseTestHooks.byPath[key]
	atomicTransformPhaseTestHooks.RUnlock()
	if hook == nil {
		return nil
	}
	return hook(phase, state)
}
