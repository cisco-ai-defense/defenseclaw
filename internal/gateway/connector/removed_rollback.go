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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// until 1.1, with removed.go: a rollback to a release that still guards
// OpenHands and OmniGent (before 1.0.5) brings back the agent files the
// removed-connector teardown changed (GAP-2136). The data swap of the
// rollback restores everything under the data folder, but these files are
// outside it: without them the older release ran without its OpenHands
// hooks.json, and its gateway writes it again only when it can probe the
// agent's version. Before it changes a file, the teardown keeps what it read
// in removedRollbackFile, in the data folder of the install that made the
// change; 'connector prepare-rollback --to-version' puts each file back when
// it is still what the teardown left (or still absent, for a file the
// teardown removed). A file changed since stays as it is.

const (
	removedRollbackFile = "removed_connectors_rollback.json"
	// removedFirstRelease is the first release without OpenHands and
	// OmniGent: a rollback to it or later brings nothing back.
	removedFirstRelease = "1.0.5"
)

type removedRollbackEntry struct {
	Connector string `json:"connector"`
	Path      string `json:"path"`
	// Original is the file as the teardown found it.
	Original []byte `json:"original"`
	Mode     uint32 `json:"mode"`
	// After is the SHA-256 of what the teardown wrote; empty when it
	// removed the file.
	After string `json:"after_sha256,omitempty"`
}

type removedRollbackRecord struct {
	Version int                    `json:"version"`
	Entries []removedRollbackEntry `json:"entries"`
}

func removedRollbackPath(dataDir string) string {
	return filepath.Join(dataDir, removedRollbackFile)
}

func loadRemovedRollback(dataDir string) (removedRollbackRecord, error) {
	record := removedRollbackRecord{Version: 1}
	data, err := os.ReadFile(removedRollbackPath(dataDir))
	if errors.Is(err, os.ErrNotExist) {
		return record, nil
	}
	if err != nil {
		return record, err
	}
	if err := json.Unmarshal(data, &record); err != nil {
		return removedRollbackRecord{Version: 1}, err
	}
	return record, nil
}

func saveRemovedRollback(dataDir string, record removedRollbackRecord) error {
	path := removedRollbackPath(dataDir)
	if len(record.Entries) == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(path, data, 0o600)
}

// recordRemovedRollback keeps original, the file at path as the teardown
// found it, before the teardown writes after (nil: removes the file). A
// path already recorded keeps its first original, the one the older
// release wrote. Best effort: a record that cannot be written only means
// the rollback cannot bring the file back.
func recordRemovedRollback(dataDir, name, path string, original []byte, mode os.FileMode, after []byte) {
	if strings.TrimSpace(dataDir) == "" {
		return
	}
	record, err := loadRemovedRollback(dataDir)
	if err != nil {
		return
	}
	sum := ""
	if after != nil {
		sum = sha256Hex(after)
	}
	for i := range record.Entries {
		if sameManagedTargetPath(record.Entries[i].Path, path) {
			record.Entries[i].After = sum
			_ = saveRemovedRollback(dataDir, record)
			return
		}
	}
	record.Entries = append(record.Entries, removedRollbackEntry{
		Connector: name, Path: path, Original: append([]byte(nil), original...), Mode: uint32(mode.Perm()), After: sum,
	})
	_ = saveRemovedRollback(dataDir, record)
}

// RemovedRollbackResult is what RestoreRemovedConnectorFilesForRollback did
// with one recorded file.
type RemovedRollbackResult struct {
	Connector string
	Path      string
	Restored  bool
	// Reason says why a file was not put back.
	Reason string
}

// RestoreRemovedConnectorFilesForRollback puts back, for a rollback to
// toVersion, the agent files the OpenHands/OmniGent teardown changed (see
// the top of this file). It does nothing for toVersion 1.0.5 or later. Every
// recorded file is handled once: the record keeps only a file that could
// not be written, so the next try can still put it back.
func RestoreRemovedConnectorFilesForRollback(dataDir, toVersion string) ([]RemovedRollbackResult, error) {
	toVersion = strings.TrimSpace(toVersion)
	if strings.TrimSpace(dataDir) == "" || toVersion == "" || compareVersion(toVersion, removedFirstRelease) >= 0 {
		return nil, nil
	}
	record, err := loadRemovedRollback(dataDir)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", removedRollbackPath(dataDir), err)
	}
	var results []RemovedRollbackResult
	var kept []removedRollbackEntry
	var failed []string
	for _, entry := range record.Entries {
		result := RemovedRollbackResult{Connector: entry.Connector, Path: entry.Path}
		restored, reason, err := restoreRemovedRollbackEntry(entry)
		switch {
		case err != nil:
			kept = append(kept, entry)
			failed = append(failed, fmt.Sprintf("%s: %v", entry.Path, err))
			result.Reason = err.Error()
		case restored:
			result.Restored = true
		default:
			result.Reason = reason
		}
		results = append(results, result)
	}
	record.Entries = kept
	if err := saveRemovedRollback(dataDir, record); err != nil {
		failed = append(failed, fmt.Sprintf("%s: %v", removedRollbackPath(dataDir), err))
	}
	if len(failed) > 0 {
		return results, fmt.Errorf("could not put back %s", strings.Join(failed, "; "))
	}
	return results, nil
}

func restoreRemovedRollbackEntry(entry removedRollbackEntry) (bool, string, error) {
	mode := os.FileMode(entry.Mode).Perm()
	if mode == 0 {
		mode = 0o600
	}
	info, err := os.Lstat(entry.Path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if entry.After != "" {
			return false, "it was removed after the upgrade", nil
		}
		if _, err := os.Stat(filepath.Dir(entry.Path)); err != nil {
			return false, "its folder is gone", nil
		}
		return true, "", atomicWriteFile(entry.Path, entry.Original, mode)
	case err != nil:
		return false, "", err
	case !info.Mode().IsRegular():
		return false, "it is no longer a regular file", nil
	case entry.After == "":
		return false, "a new file is there since the upgrade", nil
	}
	data, err := readRemovedConfig(entry.Path)
	if err != nil {
		return false, "", err
	}
	if sha256Hex(data) != entry.After {
		return false, "it changed after the upgrade", nil
	}
	if err := atomicWriteFile(entry.Path, entry.Original, info.Mode().Perm()); err != nil {
		return false, "", err
	}
	return true, "", removedKeepOwner(entry.Path, info)
}
