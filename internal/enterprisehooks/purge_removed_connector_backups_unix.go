// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

// until 1.1: the managed Linux/macOS purge keeps what is left in the
// OpenHands/OmniGent backup folders (a copy 1.0.4 saved of an edited
// module, which its leftover list told the user to copy back), the way the
// OSS uninstall does (cmd_uninstall.py _move_removed_connector_backups_out)
// (GAP-2015). Delete with internal/gateway/connector/removed.go.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// removedConnectorBackupNames are the removed connectors whose
// connector_backups/<name> folder the purge keeps.
var removedConnectorBackupNames = []string{"omnigent", "openhands"}

// removedConnectorBackupsKeptRoot is where the purge moves them: beside the
// data folder, the name the CLI uses (removed_connectors.kept_backups_root).
func removedConnectorBackupsKeptRoot(dataDir string) string {
	return filepath.Clean(dataDir) + "-removed-connector-backups"
}

// moveRemovedConnectorBackupsOut moves each removed connector's backup
// folder out of dataDir before the purge deletes it, under a new name when
// an earlier purge left one there, and returns where. A link there is not
// DefenseClaw's folder and goes with the data. It runs as the account. When
// a folder cannot be moved the purge stops and nothing is removed.
func moveRemovedConnectorBackupsOut(dataDir string) ([]string, error) {
	var kept []string
	root := removedConnectorBackupsKeptRoot(dataDir)
	if info, err := os.Lstat(filepath.Join(dataDir, "connector_backups")); err != nil || !info.IsDir() {
		return nil, nil
	}
	for _, name := range removedConnectorBackupNames {
		path := filepath.Join(dataDir, "connector_backups", name)
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return kept, fmt.Errorf("inspect %s: %w", path, err)
		}
		if !info.IsDir() {
			continue
		}
		if info, err := os.Lstat(root); err == nil && !info.IsDir() {
			return kept, fmt.Errorf("could not keep %s (the copies DefenseClaw saved of your %s files): %s is in the way and is not a folder; move it, then rerun the purge", path, name, root)
		}
		if err := os.MkdirAll(root, 0o700); err != nil {
			return kept, fmt.Errorf("could not keep %s (the copies DefenseClaw saved of your %s files): %w", path, name, err)
		}
		target := filepath.Join(root, name)
		for count := 2; ; count++ {
			if _, err := os.Lstat(target); errors.Is(err, os.ErrNotExist) {
				break
			}
			target = filepath.Join(root, fmt.Sprintf("%s-%d", name, count))
		}
		if err := os.Rename(path, target); err != nil {
			return kept, fmt.Errorf("could not keep %s (the copies DefenseClaw saved of your %s files) by moving it to %s: %w; move it out yourself, then rerun the purge", path, name, target, err)
		}
		kept = append(kept, target)
	}
	return kept, nil
}

// unrestorableConnectorBackupsKeptRoot is where a purge keeps the connector
// backup records it cannot restore anything from.
func unrestorableConnectorBackupsKeptRoot(dataDir string) string {
	return filepath.Clean(dataDir) + "-unrestorable-connector-backups"
}

// unrestorableConnectorBackup reports a record in connector_backups/<name>/
// that names no file DefenseClaw can put back: not a JSON object, or one with
// neither a backup version nor a path (what an earlier failed install, or a
// hand edit, can leave). Its connector's teardown refuses it, and the purge
// kept the whole folder for it (rel-1-0-2 GAP-0576).
func unrestorableConnectorBackup(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var record map[string]json.RawMessage
	if json.Unmarshal(data, &record) != nil {
		return true
	}
	_, version := record["version"]
	_, named := record["path"]
	return !version && !named
}

// moveUnrestorableConnectorBackupsOut moves, before a purge tears the
// connectors down, every connector backup record that names no file
// (unrestorableConnectorBackup) to ~/.defenseclaw-unrestorable-connector-backups/<connector>/,
// so the teardown and the purge go on and the account keeps the bytes. It
// returns the folders it moved records to.
func moveUnrestorableConnectorBackupsOut(dataDir string) ([]string, error) {
	backups := filepath.Join(dataDir, "connector_backups")
	if info, err := os.Lstat(backups); err != nil || !info.IsDir() {
		return nil, nil
	}
	connectors, err := os.ReadDir(backups)
	if err != nil {
		return nil, err
	}
	var kept []string
	root := unrestorableConnectorBackupsKeptRoot(dataDir)
	for _, entry := range connectors {
		if !entry.IsDir() {
			continue
		}
		dir := filepath.Join(backups, entry.Name())
		records, err := os.ReadDir(dir)
		if err != nil {
			return kept, err
		}
		moved := false
		for _, record := range records {
			if !strings.HasSuffix(record.Name(), ".json") || !unrestorableConnectorBackup(filepath.Join(dir, record.Name())) {
				continue
			}
			if info, err := os.Lstat(root); err == nil && !info.IsDir() {
				return kept, fmt.Errorf("could not keep %s: %s is in the way and is not a folder; move it, then rerun the purge", filepath.Join(dir, record.Name()), root)
			}
			target := filepath.Join(root, entry.Name())
			if err := os.MkdirAll(target, 0o700); err != nil {
				return kept, fmt.Errorf("could not keep %s: %w", filepath.Join(dir, record.Name()), err)
			}
			name := filepath.Join(target, record.Name())
			for count := 2; ; count++ {
				if _, err := os.Lstat(name); errors.Is(err, os.ErrNotExist) {
					break
				}
				name = filepath.Join(target, fmt.Sprintf("%s-%d", record.Name(), count))
			}
			if err := os.Rename(filepath.Join(dir, record.Name()), name); err != nil {
				return kept, fmt.Errorf("could not keep %s by moving it to %s: %w; move it out yourself, then rerun the purge", filepath.Join(dir, record.Name()), name, err)
			}
			moved = true
		}
		if moved {
			kept = append(kept, filepath.Join(root, entry.Name()))
			_ = os.Remove(dir) // only when nothing else is in it
		}
	}
	return kept, nil
}
