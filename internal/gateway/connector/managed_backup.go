// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

const managedBackupVersion = 1
const managedBackupMissingHash = "missing"

type managedFileBackup struct {
	Version        int    `json:"version"`
	Connector      string `json:"connector"`
	LogicalName    string `json:"logical_name"`
	Path           string `json:"path"`
	Existed        bool   `json:"existed"`
	Mode           uint32 `json:"mode,omitempty"`
	PristineSHA256 string `json:"pristine_sha256"`
	PostSHA256     string `json:"post_sha256,omitempty"`
	PristineBytes  []byte `json:"pristine_bytes,omitempty"`
	CapturedAt     string `json:"captured_at"`
	UpdatedAt      string `json:"updated_at,omitempty"`
}

func managedFileBackupPath(dataDir, connectorName, logicalName string) string {
	name := strings.NewReplacer("/", "_", "\\", "_", ":", "_", " ", "_").Replace(logicalName)
	if name == "" {
		name = "config"
	}
	return filepath.Join(dataDir, "connector_backups", connectorName, name+".json")
}

func managedFileBackupTargetPath(dataDir, connectorName, logicalName, fallback string) string {
	b, err := loadManagedFileBackupPath(managedFileBackupPath(dataDir, connectorName, logicalName))
	if err == nil && b.Connector == connectorName && b.LogicalName == logicalName && strings.TrimSpace(b.Path) != "" {
		return b.Path
	}
	return fallback
}

func captureManagedFileBackup(dataDir, connectorName, logicalName, targetPath string) error {
	boundPath, err := normalizeManagedTargetPath(targetPath)
	if err != nil {
		return fmt.Errorf("bind managed backup target: %w", err)
	}
	backupPath := managedFileBackupPath(dataDir, connectorName, logicalName)
	existing, err := loadManagedFileBackupPath(backupPath)
	if err == nil {
		_, err = validateManagedFileBackupTarget(existing, connectorName, logicalName, boundPath)
		return err
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("load managed backup: %w", err)
	}

	b := managedFileBackup{
		Version:     managedBackupVersion,
		Connector:   connectorName,
		LogicalName: logicalName,
		Path:        boundPath,
		CapturedAt:  time.Now().UTC().Format(time.RFC3339Nano),
	}

	data, info, err := readManagedTarget(boundPath)
	if err != nil {
		return err
	}
	if info != nil {
		b.Existed = true
		b.Mode = uint32(info.Mode().Perm())
		b.PristineBytes = data
		b.PristineSHA256 = sha256Hex(data)
	} else {
		b.PristineSHA256 = managedBackupMissingHash
	}
	return writeManagedFileBackup(backupPath, b)
}

func updateManagedFileBackupPostHash(dataDir, connectorName, logicalName, targetPath string) error {
	backupPath := managedFileBackupPath(dataDir, connectorName, logicalName)
	b, err := loadManagedFileBackupPath(backupPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	boundPath, err := validateManagedFileBackupTarget(b, connectorName, logicalName, targetPath)
	if err != nil {
		return err
	}
	data, info, err := readManagedTarget(boundPath)
	if err != nil {
		return err
	}
	nextHash := managedFileSnapshotHash(nil, false)
	if info != nil {
		nextHash = managedFileSnapshotHash(data, true)
	}
	return updateManagedFileBackupPostHashValue(dataDir, connectorName, logicalName, boundPath, nextHash)
}

// updateManagedFileBackupPostHashValue records the exact bytes the connector
// committed, rather than re-reading a path that an external editor can change
// between replacement and backup publication. If the path later drifts, its
// hash no longer matches and teardown automatically uses surgical cleanup.
func updateManagedFileBackupPostHashValue(
	dataDir, connectorName, logicalName, targetPath, nextHash string,
) error {
	backupPath := managedFileBackupPath(dataDir, connectorName, logicalName)
	b, err := loadManagedFileBackupPath(backupPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if _, err := validateManagedFileBackupTarget(b, connectorName, logicalName, targetPath); err != nil {
		return err
	}
	if nextHash == "" {
		return fmt.Errorf("managed backup post hash is empty")
	}
	if b.PostSHA256 == nextHash {
		return nil
	}
	b.PostSHA256 = nextHash
	b.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return writeManagedFileBackup(backupPath, b)
}

func managedFileSnapshotHash(data []byte, exists bool) string {
	if !exists {
		return managedBackupMissingHash
	}
	return sha256Hex(data)
}

func managedFileBackupExpectedHash(b *managedFileBackup) string {
	if b == nil {
		return ""
	}
	if b.PostSHA256 != "" {
		return b.PostSHA256
	}
	return b.PristineSHA256
}

func managedFileBackupMatchesSnapshot(b *managedFileBackup, data []byte, exists bool) bool {
	return b != nil && managedFileBackupExpectedHash(b) == managedFileSnapshotHash(data, exists)
}

func restoreManagedFileBackupIfUnchanged(dataDir, connectorName, logicalName, targetPath string) (bool, error) {
	backupPath := managedFileBackupPath(dataDir, connectorName, logicalName)
	b, err := loadManagedFileBackupPath(backupPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	boundPath, err := validateManagedFileBackupTarget(b, connectorName, logicalName, targetPath)
	if err != nil {
		return false, err
	}

	data, info, err := readManagedTarget(boundPath)
	if err != nil {
		return false, err
	}
	currentHash := managedBackupMissingHash
	if info != nil {
		currentHash = sha256Hex(data)
	}
	expectedHash := b.PostSHA256
	if expectedHash == "" {
		expectedHash = b.PristineSHA256
	}
	if currentHash != expectedHash {
		return false, nil
	}

	if b.Existed {
		mode := os.FileMode(b.Mode)
		if mode == 0 {
			mode = 0o600
		}
		if err := atomicWriteFile(boundPath, b.PristineBytes, mode); err != nil {
			return false, err
		}
	} else if err := os.Remove(boundPath); err != nil && !os.IsNotExist(err) {
		return false, err
	}
	if err := os.Remove(backupPath); err != nil && !os.IsNotExist(err) {
		return false, err
	}
	return true, nil
}

func normalizeManagedTargetPath(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("target path is empty")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve target path %q: %w", path, err)
	}
	return filepath.Clean(abs), nil
}

// validateManagedFileBackupTarget binds restore metadata to both its logical
// owner and the exact lexical target captured during setup. It deliberately
// does not resolve symlinks: following a retargeted link during teardown would
// weaken the same-file invariant this check protects.
func validateManagedFileBackupTarget(b managedFileBackup, connectorName, logicalName, targetPath string) (string, error) {
	if b.Connector != connectorName || b.LogicalName != logicalName {
		return "", fmt.Errorf(
			"managed backup identity mismatch: captured %s/%s, requested %s/%s",
			b.Connector, b.LogicalName, connectorName, logicalName,
		)
	}
	captured, err := normalizeManagedTargetPath(b.Path)
	if err != nil {
		return "", fmt.Errorf("invalid managed backup target: %w", err)
	}
	requested, err := normalizeManagedTargetPath(targetPath)
	if err != nil {
		return "", fmt.Errorf("invalid requested restore target: %w", err)
	}
	equal := captured == requested
	if runtime.GOOS == "windows" {
		equal = strings.EqualFold(captured, requested)
	}
	if !equal {
		return "", fmt.Errorf("managed backup target mismatch: captured %q, requested %q", captured, requested)
	}
	return captured, nil
}

func discardManagedFileBackup(dataDir, connectorName, logicalName string) {
	_ = os.Remove(managedFileBackupPath(dataDir, connectorName, logicalName))
}

func loadManagedFileBackupPath(path string) (managedFileBackup, error) {
	var b managedFileBackup
	data, err := os.ReadFile(path)
	if err != nil {
		return b, err
	}
	if err := json.Unmarshal(data, &b); err != nil {
		return b, err
	}
	if b.Version != managedBackupVersion {
		return b, fmt.Errorf("unsupported managed backup version %d", b.Version)
	}
	return b, nil
}

func writeManagedFileBackup(path string, b managedFileBackup) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	// Ensure the per-connector backup directory is owner-only (0o700)
	// before atomicWriteFile lays down the file. atomicWriteFile uses
	// MkdirAll(_, 0o755) by design — that perm is right for parent
	// dirs of user-owned config files (e.g. ~/.codex/) but wrong for
	// our own ${data_dir}/connector_backups/<connector>/ tree, which
	// would otherwise be world-readable. Listing the connector_backups
	// dir leaks which connectors the operator has installed; the
	// payload itself already has 0o600 from atomicWriteFile.
	if err := ensureManagedBackupDirRestricted(filepath.Dir(path)); err != nil {
		return err
	}
	return atomicWriteFile(path, append(data, '\n'), 0o600)
}

// ensureManagedBackupDirRestricted creates *dir* with mode 0o700 if it
// does not exist, and tightens an existing dir down to 0o700 if a prior
// install (or umask) left it world-readable. Failures are returned
// rather than swallowed because the per-connector dir is the parent of
// every backup; if we cannot guarantee 0o700 here, the operator should
// see the error rather than discover later that the backup payload was
// listable.
func ensureManagedBackupDirRestricted(dir string) error {
	if dir == "" {
		return nil
	}
	if err := safefile.ProtectDirectory(dir); err != nil {
		return fmt.Errorf("create managed backup dir %s: %w", dir, err)
	}
	return nil
}

func readManagedTarget(path string) ([]byte, os.FileInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("read %s: %w", path, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("stat %s: %w", path, err)
	}
	return data, info, nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
