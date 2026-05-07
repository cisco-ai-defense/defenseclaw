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
	"strings"
	"time"
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

func captureManagedFileBackup(dataDir, connectorName, logicalName, targetPath string) error {
	backupPath := managedFileBackupPath(dataDir, connectorName, logicalName)
	if _, err := os.Stat(backupPath); err == nil {
		return nil
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("stat managed backup: %w", err)
	}

	b := managedFileBackup{
		Version:     managedBackupVersion,
		Connector:   connectorName,
		LogicalName: logicalName,
		Path:        targetPath,
		CapturedAt:  time.Now().UTC().Format(time.RFC3339Nano),
	}

	data, info, err := readManagedTarget(targetPath)
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
	data, info, err := readManagedTarget(targetPath)
	if err != nil {
		return err
	}
	if info != nil {
		b.PostSHA256 = sha256Hex(data)
	} else {
		b.PostSHA256 = managedBackupMissingHash
	}
	b.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return writeManagedFileBackup(backupPath, b)
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

	data, info, err := readManagedTarget(targetPath)
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
		if err := atomicWriteFile(targetPath, b.PristineBytes, mode); err != nil {
			return false, err
		}
	} else if err := os.Remove(targetPath); err != nil && !os.IsNotExist(err) {
		return false, err
	}
	if err := os.Remove(backupPath); err != nil && !os.IsNotExist(err) {
		return false, err
	}
	return true, nil
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
	return atomicWriteFile(path, append(data, '\n'), 0o600)
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
