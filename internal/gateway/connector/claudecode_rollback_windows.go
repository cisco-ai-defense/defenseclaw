// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

const claudeCodeRollbackWitnessName = "claudecode-settings.before-rollback.witness.json"

// Inert backup evidence, never an active CAS receipt. The prepared receipt
// authenticates the converter's exact publication after its active receipts
// have been cleaned up. Restored similarly permits an identity-bound retry.
type claudeCodeRollbackWitness struct {
	Version    int                       `json:"version"`
	Backup     atomicTransformV2Artifact `json:"backup"`
	Conversion atomicTransformV2Receipt  `json:"conversion"`
	Restored   *atomicTransformV2Receipt `json:"restored,omitempty"`
}

func transformClaudeCodeRollback(path string, opts SetupOpts, transform func([]byte, bool) (atomicTransformResult, error)) error {
	return atomicTransformFileV2(path, opts.DataDir, 0o600, atomicTransformV2Options{
		beforeCommit: func(receipt atomicTransformV2Receipt) error {
			dir, err := openClaudeCodeRollbackEvidence(opts.DataDir, false)
			if err != nil {
				return err
			}
			if dir == nil {
				return fmt.Errorf("rollback backup disappeared before publication")
			}
			defer dir.Close()
			backup, err := atomicTransformBoundInspectPrivate(dir, claudeCodeRollbackBackupName, atomicTransformMaxConfigBytes)
			if err != nil {
				return err
			}
			converted, count, err := claudeCodeRollbackConversion(opts, path)(backup.data)
			if err != nil || !backup.exists || count == 0 || backup.digest != receipt.Old.SHA256 ||
				atomicTransformDigest(converted) != receipt.Stage.SHA256 {
				return errors.Join(fmt.Errorf("rollback backup does not match the prepared conversion"), err)
			}
			witness := claudeCodeRollbackWitness{Version: 1,
				Backup: atomicTransformV2ArtifactFromState(claudeCodeRollbackBackupName, backup), Conversion: receipt}
			return writeClaudeCodeRollbackWitness(dir, witness)
		},
	}, transform)
}

func openClaudeCodeRollbackEvidence(dataDir string, create bool) (*atomicTransformBoundDirectory, error) {
	if err := atomicTransformValidateNoReparsePathPlatform(dataDir); err != nil {
		return nil, err
	}
	if err := safefile.ValidatePrivateDirectory(dataDir); err != nil {
		return nil, err
	}
	path := filepath.Join(dataDir, "backups")
	if create {
		if err := os.Mkdir(path, 0o700); err == nil {
			if err := safefile.ProtectDirectory(path); err != nil {
				return nil, err
			}
		} else if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
	}
	if err := atomicTransformValidateNoReparsePathPlatform(path); err != nil {
		return nil, err
	}
	dir, err := bindAtomicTransformDirectory(path)
	if errors.Is(err, os.ErrNotExist) && !create {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := dir.validatePrivate(); err != nil {
		_ = dir.Close()
		return nil, err
	}
	return dir, nil
}

func writeClaudeCodeRollbackBackup(dataDir string, data []byte) error {
	dir, err := openClaudeCodeRollbackEvidence(dataDir, true)
	if err != nil {
		return err
	}
	defer dir.Close()
	return writeClaudeCodeRollbackEvidence(dir, claudeCodeRollbackBackupName, data)
}

// Do not resolve the destination through a link. Private bound publication is
// a plain rename, not a nested V2 transform (which would reenter its lock).
func writeClaudeCodeRollbackEvidence(dir *atomicTransformBoundDirectory, name string, data []byte) error {
	return writeClaudeCodeRollbackEvidenceWithPublisher(dir, name, data, atomicFilePublish)
}

func writeClaudeCodeRollbackEvidenceWithPublisher(
	dir *atomicTransformBoundDirectory, name string, data []byte, publish atomicFilePublisher,
) error {
	if _, err := atomicTransformBoundInspectPrivate(dir, name, atomicTransformMaxConfigBytes); err != nil {
		return err
	}
	temp, tempPath, err := atomicFileCreateTemp(dir.path, 0o600)
	if err != nil {
		return err
	}
	var staged atomicTransformArtifactState
	tempOpen, published := true, false
	defer func() {
		if tempOpen {
			// Capture only the inode still held by our original create handle.
			// Failure to authenticate it means retain, never path-delete.
			staged, _ = atomicTransformBoundStateFromOpen(temp, filepath.Base(tempPath), atomicTransformMaxConfigBytes)
			_ = temp.Close()
		}
		if !published && staged.exists {
			_ = atomicTransformBoundDeleteExact(dir, filepath.Base(tempPath), staged)
		}
	}()
	if _, err := temp.Write(data); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	staged, err = atomicTransformBoundStateFromOpen(temp, filepath.Base(tempPath), atomicTransformMaxConfigBytes)
	closeErr := temp.Close()
	tempOpen = false
	if err != nil || closeErr != nil {
		return errors.Join(err, closeErr)
	}
	err = publish(tempPath, filepath.Join(dir.path, name), staged.info, 0o600)
	published = err == nil
	return err
}

func writeClaudeCodeRollbackWitness(dir *atomicTransformBoundDirectory, witness claudeCodeRollbackWitness) error {
	data, err := json.Marshal(witness)
	if err != nil {
		return err
	}
	if len(data) > atomicTransformMaxIntentBytes {
		return fmt.Errorf("rollback conversion witness exceeds %d-byte evidence limit", atomicTransformMaxIntentBytes)
	}
	return writeClaudeCodeRollbackEvidence(dir, claudeCodeRollbackWitnessName, data)
}

func loadClaudeCodeRollbackWitness(path string, opts SetupOpts) (claudeCodeRollbackWitness, atomicTransformArtifactState, atomicTransformArtifactState, error) {
	var witness claudeCodeRollbackWitness
	dir, err := openClaudeCodeRollbackEvidence(opts.DataDir, false)
	if err != nil || dir == nil {
		return witness, atomicTransformArtifactState{}, atomicTransformArtifactState{}, err
	}
	defer dir.Close()
	backup, err := atomicTransformBoundInspectPrivate(dir, claudeCodeRollbackBackupName, atomicTransformMaxConfigBytes)
	if err != nil {
		return witness, backup, atomicTransformArtifactState{}, err
	}
	proof, err := atomicTransformBoundInspectPrivate(dir, claudeCodeRollbackWitnessName, atomicTransformMaxIntentBytes)
	if err != nil {
		return witness, backup, proof, err
	}
	if !backup.exists && !proof.exists {
		return witness, backup, proof, nil
	}
	if !backup.exists || !proof.exists {
		return witness, backup, proof, fmt.Errorf("rollback conversion backup or identity witness is missing")
	}
	decoder := json.NewDecoder(bytes.NewReader(proof.data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&witness); err != nil {
		return witness, backup, proof, fmt.Errorf("invalid rollback conversion witness: %w", err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) || witness.Version != 1 {
		return witness, backup, proof, fmt.Errorf("invalid rollback conversion witness version or trailing data")
	}
	if !atomicTransformV2OldExactMatches(witness.Backup, backup) || witness.Backup.Name != claudeCodeRollbackBackupName ||
		backup.digest != witness.Conversion.Old.SHA256 {
		return witness, backup, proof, fmt.Errorf("rollback backup identity or content no longer matches its conversion")
	}
	converted, count, err := claudeCodeRollbackConversion(opts, path)(backup.data)
	if err != nil || count == 0 || atomicTransformDigest(converted) != witness.Conversion.Stage.SHA256 {
		return witness, backup, proof, errors.Join(fmt.Errorf("rollback backup does not reproduce the witnessed conversion"), err)
	}
	for _, receipt := range []*atomicTransformV2Receipt{&witness.Conversion, witness.Restored} {
		if receipt == nil {
			continue
		}
		logical, base, err := atomicTransformV2BasePath(path, opts.DataDir)
		if err != nil {
			return witness, backup, proof, err
		}
		if err := validateAtomicTransformV2Receipt(*receipt, logical, opts.DataDir, base, filepath.Join(dir.path, claudeCodeRollbackWitnessName)); err != nil {
			return witness, backup, proof, err
		}
		if receipt.Phase != atomicTransformV2Prepared || !receipt.OldExists || receipt.Remove {
			return witness, backup, proof, fmt.Errorf("rollback witness is not a prepared file replacement")
		}
		stateID, err := atomicTransformDirectoryIdentity(opts.DataDir)
		if err != nil || stateID != receipt.StateDirIdentity {
			return witness, backup, proof, errors.Join(fmt.Errorf("rollback witness state directory changed"), err)
		}
		parentID, err := atomicTransformDirectoryIdentity(filepath.Dir(receipt.TargetPath))
		if err != nil || parentID != receipt.TargetParentIdentity {
			return witness, backup, proof, errors.Join(fmt.Errorf("rollback witness settings directory changed"), err)
		}
	}
	if witness.Restored != nil && (witness.Restored.Stage.SHA256 != backup.digest ||
		witness.Restored.Old.Identity != witness.Conversion.Stage.Identity ||
		witness.Restored.Old.SHA256 != witness.Conversion.Stage.SHA256) {
		return witness, backup, proof, fmt.Errorf("restored publication is unrelated to the witnessed conversion")
	}
	return witness, backup, proof, nil
}

func claudeCodeRollbackSnapshotState(snapshot atomicFileSnapshot) atomicTransformArtifactState {
	return atomicTransformArtifactState{exists: snapshot.exists, data: snapshot.data, info: snapshot.info,
		digest: atomicTransformDigest(snapshot.data), size: int64(len(snapshot.data)), identity: snapshot.identity,
		protectionDigest: snapshot.protectionDigest, metadataDigest: snapshot.metadataDigest,
		preservedMetadataDigest: snapshot.preservedMetadataDigest, canonicalEAMetadataDigest: snapshot.canonicalEAMetadataDigest,
		stageOwnedMetadataDigest: snapshot.stageOwnedMetadataDigest, ownerGroupDigest: snapshot.ownerGroupDigest,
		creationTime: snapshot.creationTime, lastWriteTime: snapshot.lastWriteTime, linkCount: snapshot.linkCount}
}

// RestoreHooksAfterRollback is deliberately narrower than Setup: it recovers
// owned CAS first, then reverses only this converter's exact publication.
func (c *ClaudeCodeConnector) RestoreHooksAfterRollback(opts SetupOpts) (int, error) {
	if opts.ManagedEnterprise {
		return 0, nil
	}
	path := claudeCodeSettingsPath()
	if _, err := os.Stat(filepath.Dir(path)); errors.Is(err, os.ErrNotExist) {
		// An unconfigured agent has no directory in which to take its advisory
		// settings lock. Recovery-only still processes any owned publication;
		// it does not create a new agent profile just to report a no-op.
		stateDir, err := prepareAtomicTransformStateDir(opts.DataDir)
		if err == nil {
			err = recoverAtomicTransformV2(path, stateDir)
		}
		if err == nil {
			if _, parentErr := os.Stat(filepath.Dir(path)); errors.Is(parentErr, os.ErrNotExist) {
				_, _, proof, proofErr := loadClaudeCodeRollbackWitness(path, opts)
				if proofErr == nil && !proof.exists {
					return 0, nil
				}
				err = errors.Join(fmt.Errorf("settings directory is missing but rollback evidence exists"), proofErr)
			}
		}
		if err != nil {
			return 0, fmt.Errorf("Claude Code rollback protection could not be verified or restored; retained recovery evidence: %w", err)
		}
	}
	var witness claudeCodeRollbackWitness
	var backup, proof, authorized atomicTransformArtifactState
	restore, restored := false, 0
	err := withFileLock(path, func() error {
		return atomicTransformFileV2(path, opts.DataDir, 0o600, atomicTransformV2Options{
			preserveExistingProtection: true,
			validateSnapshot: func(snapshot atomicFileSnapshot) error {
				var err error
				witness, backup, proof, err = loadClaudeCodeRollbackWitness(path, opts)
				if err != nil {
					return err
				}
				restore = false
				if !proof.exists {
					return nil // converter had no entries to change
				}
				authorized = claudeCodeRollbackSnapshotState(snapshot)
				if bytes.Equal(snapshot.data, backup.data) &&
					(atomicTransformV2OldExactMatches(witness.Conversion.Old, authorized) ||
						(witness.Restored != nil && atomicTransformV2PublishedTargetMatches(*witness.Restored, authorized))) {
					return nil
				}
				if !atomicTransformV2PublishedTargetMatches(witness.Conversion, authorized) {
					return fmt.Errorf("settings are not the exact witnessed rollback publication; refusing to overwrite foreign changes")
				}
				restore = true
				return nil
			},
			beforeCommit: func(receipt atomicTransformV2Receipt) error {
				if !restore || !atomicTransformV2OldExactMatches(receipt.Old, authorized) || receipt.Stage.SHA256 != backup.digest {
					return fmt.Errorf("inverse transaction no longer matches the witnessed publication")
				}
				_, currentBackup, currentProof, err := loadClaudeCodeRollbackWitness(path, opts)
				if err != nil || !atomicTransformArtifactStatesEqualExact(backup, currentBackup) ||
					!atomicTransformArtifactStatesEqualExact(proof, currentProof) {
					return errors.Join(fmt.Errorf("rollback evidence changed before inverse publication"), err)
				}
				dir, err := openClaudeCodeRollbackEvidence(opts.DataDir, false)
				if err != nil || dir == nil {
					return errors.Join(fmt.Errorf("rollback evidence directory disappeared"), err)
				}
				defer dir.Close()
				witness.Restored = &receipt
				return writeClaudeCodeRollbackWitness(dir, witness)
			},
		}, func(current []byte, exists bool) (atomicTransformResult, error) {
			if !restore {
				return atomicTransformResult{Data: current, Remove: !exists}, nil
			}
			_, restored, _ = claudeCodeRollbackConversion(opts, path)(backup.data)
			return atomicTransformResult{Data: backup.data}, nil
		})
	})
	if err != nil {
		return 0, fmt.Errorf("Claude Code rollback protection could not be verified or restored; retained recovery evidence: %w", err)
	}
	return restored, nil
}
