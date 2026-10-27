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
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
