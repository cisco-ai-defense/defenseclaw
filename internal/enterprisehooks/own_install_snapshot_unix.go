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

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"
)

// OwnInstallSnapshotName is the file in ~/.defenseclaw that keeps, while
// the computer is managed, the account's own per-user install files the
// enrollment changes: the hook scripts, hook tokens and hook configs in
// hooks/, the connector backups, the hook contract lock and the session and
// Hermes state files, and each agent config file those backups name. The
// managed enrollment shares ~/.defenseclaw with that install, and its
// uninstall used to leave the install's files rewritten or removed; the
// uninstall now puts them back byte for byte (rel-1-0-6 GAP-0178).
const OwnInstallSnapshotName = "managed-own-install-snapshot.json"

const ownInstallSnapshotVersion = 1

// ownInstallSnapshotMaxBytes bounds what the snapshot keeps: a larger set is
// not kept, and the uninstall behaves as before for that account.
const ownInstallSnapshotMaxBytes = 16 << 20

// ownInstallSnapshotDirs are the folders in ~/.defenseclaw whose whole
// content the snapshot keeps; files the enrollment adds there go at the
// restore.
var ownInstallSnapshotDirs = []string{"hooks", "connector_backups"}

// ownInstallSnapshotTopFiles are the files directly in ~/.defenseclaw the
// enrollment writes; one the snapshot did not find goes at the restore.
var ownInstallSnapshotTopFiles = []string{
	"hook_contract_lock.json",
	"hermes-home-setup.json",
	".hermes-lifecycle.lock",
	"removed-connectors-logged.json",
	"session-facts.json",
	"watcher-created-dirs.json",
	PersonalClaudeHookCopyName,
}

type ownInstallSnapshotFile struct {
	Path string `json:"path"`
	Mode uint32 `json:"mode"`
	Data []byte `json:"data"`
}

type ownInstallSnapshot struct {
	Version   int                      `json:"version"`
	CreatedAt string                   `json:"created_at"`
	Files     []ownInstallSnapshotFile `json:"files"`
	Dirs      []string                 `json:"dirs"`
	Agent     []ownInstallSnapshotFile `json:"agent_configs"`
}

// PreserveOwnInstall keeps, once, the account's own per-user install files
// the enrollment is about to change (see OwnInstallSnapshotName). It runs as
// the account, before the first managed write. A folder that holds no own
// install, or a snapshot that is already there, changes nothing. A
// Claude Code hook script that already is the enrollment's blocker is not
// kept: the restore must never put the blocker back.
func PreserveOwnInstall(home, dataDir string) error {
	own, err := HoldsPerUserInstall(dataDir)
	if err != nil || !own {
		return err
	}
	path := filepath.Join(dataDir, OwnInstallSnapshotName)
	if _, err := os.Lstat(path); err == nil || !errors.Is(err, os.ErrNotExist) {
		return err
	}
	snapshot := ownInstallSnapshot{Version: ownInstallSnapshotVersion, CreatedAt: time.Now().UTC().Format(time.RFC3339)}
	total := 0
	keep := func(list *[]ownInstallSnapshotFile, abs, name string) (bool, error) {
		info, err := os.Lstat(abs)
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if !info.Mode().IsRegular() {
			return false, nil
		}
		data, err := os.ReadFile(abs)
		if err != nil {
			return false, err
		}
		total += len(data)
		*list = append(*list, ownInstallSnapshotFile{Path: name, Mode: uint32(info.Mode().Perm()), Data: data})
		return true, nil
	}
	for _, dir := range ownInstallSnapshotDirs {
		root := filepath.Join(dataDir, dir)
		err := filepath.WalkDir(root, func(abs string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				if errors.Is(walkErr, os.ErrNotExist) {
					return nil
				}
				return walkErr
			}
			rel, err := filepath.Rel(dataDir, abs)
			if err != nil {
				return err
			}
			if entry.IsDir() {
				snapshot.Dirs = append(snapshot.Dirs, rel)
				return nil
			}
			if rel == filepath.Join("hooks", "claude-code-hook.sh") {
				if data, err := os.ReadFile(abs); err == nil && string(data) == PersonalClaudeHookBlocker {
					return nil
				}
			}
			_, err = keep(&snapshot.Files, abs, rel)
			return err
		})
		if err != nil {
			return fmt.Errorf("keep the own install's %s: %w", dir, err)
		}
	}
	for _, name := range ownInstallSnapshotTopFiles {
		if _, err := keep(&snapshot.Files, filepath.Join(dataDir, name), name); err != nil {
			return fmt.Errorf("keep the own install's %s: %w", name, err)
		}
	}
	for _, agentPath := range ownInstallBackedUpAgentConfigs(home, snapshot.Files) {
		if _, err := keep(&snapshot.Agent, agentPath, agentPath); err != nil {
			return fmt.Errorf("keep %s: %w", agentPath, err)
		}
	}
	if total > ownInstallSnapshotMaxBytes {
		return nil
	}
	data, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	return writeOwnInstallFile(path, data, 0o600)
}

// ownInstallBackedUpAgentConfigs are the agent config files inside home that
// the kept connector backup records name.
func ownInstallBackedUpAgentConfigs(home string, files []ownInstallSnapshotFile) []string {
	var out []string
	for _, file := range files {
		record, ok := ownInstallBackupRecord(file)
		if !ok || !pathInside(home, record.Path) || slices.Contains(out, record.Path) {
			continue
		}
		out = append(out, record.Path)
	}
	sort.Strings(out)
	return out
}

type ownInstallBackupRecordFields struct {
	Path           string `json:"path"`
	Existed        bool   `json:"existed"`
	PristineSHA256 string `json:"pristine_sha256"`
}

// ownInstallBackupRecord parses a kept connector backup record
// (connector_backups/<connector>/<name>.json).
func ownInstallBackupRecord(file ownInstallSnapshotFile) (ownInstallBackupRecordFields, bool) {
	var record ownInstallBackupRecordFields
	parts := strings.Split(filepath.ToSlash(file.Path), "/")
	if len(parts) != 3 || parts[0] != "connector_backups" || !strings.HasSuffix(parts[2], ".json") {
		return record, false
	}
	if json.Unmarshal(file.Data, &record) != nil || !filepath.IsAbs(record.Path) || filepath.Clean(record.Path) != record.Path {
		return record, false
	}
	return record, true
}

// RestoreOwnInstall puts back, as the account and after the uninstall
// removed the account's managed registrations, what PreserveOwnInstall kept:
// every kept file in hooks/, connector_backups/ and the kept top-level
// files, byte for byte and with its mode; the files the enrollment added
// there go. An agent config file a kept backup names is put back only when
// the uninstall left it exactly as that backup's pristine content (the
// managed teardown restored the content from before the per-user install,
// so nothing written while the computer was managed is lost); otherwise it
// stays as it is and changed names it. restored reports whether a snapshot
// was there; the snapshot goes once everything is back.
func RestoreOwnInstall(home, dataDir string) (restored bool, changed []string, err error) {
	path := filepath.Join(dataDir, OwnInstallSnapshotName)
	snapshot, found, err := loadOwnInstallSnapshot(dataDir)
	if err != nil || !found {
		return false, nil, err
	}
	kept := map[string]bool{}
	for _, file := range snapshot.Files {
		rel := filepath.Clean(file.Path)
		if filepath.IsAbs(rel) || rel == "." || strings.HasPrefix(rel, "..") {
			return false, nil, fmt.Errorf("%s names %q, outside the folder", path, file.Path)
		}
		kept[rel] = true
	}
	// What the enrollment added to the kept folders and files goes first.
	for _, dir := range ownInstallSnapshotDirs {
		root := filepath.Join(dataDir, dir)
		var added, addedDirs []string
		_ = filepath.WalkDir(root, func(abs string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			rel, relErr := filepath.Rel(dataDir, abs)
			if relErr != nil {
				return nil
			}
			if entry.IsDir() {
				if !slices.Contains(snapshot.Dirs, rel) {
					addedDirs = append(addedDirs, abs)
				}
				return nil
			}
			if !kept[rel] {
				added = append(added, abs)
			}
			return nil
		})
		for _, abs := range added {
			if err := os.Remove(abs); err != nil && !errors.Is(err, os.ErrNotExist) {
				return false, nil, err
			}
		}
		for i := len(addedDirs) - 1; i >= 0; i-- {
			_ = os.Remove(addedDirs[i])
		}
	}
	for _, name := range ownInstallSnapshotTopFiles {
		if kept[name] {
			continue
		}
		if err := os.Remove(filepath.Join(dataDir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return false, nil, err
		}
	}
	for _, dir := range snapshot.Dirs {
		if err := os.MkdirAll(filepath.Join(dataDir, dir), 0o700); err != nil {
			return false, nil, err
		}
	}
	for _, file := range snapshot.Files {
		if file.Path == filepath.Join("hooks", "claude-code-hook.sh") && string(file.Data) == PersonalClaudeHookBlocker {
			continue
		}
		if err := writeOwnInstallFile(filepath.Join(dataDir, filepath.Clean(file.Path)), file.Data, os.FileMode(file.Mode).Perm()); err != nil {
			return false, nil, err
		}
	}
	for _, agent := range snapshot.Agent {
		pristine, ok := ownInstallPristineOf(snapshot.Files, agent.Path)
		if !ok || !pathInside(home, agent.Path) {
			continue
		}
		if current, err := os.Lstat(agent.Path); err == nil && current.Mode().IsRegular() {
			if data, err := os.ReadFile(agent.Path); err == nil && string(data) == string(agent.Data) {
				// The enrollment left it as the own install had it.
				if current.Mode().Perm() != os.FileMode(agent.Mode).Perm() {
					if err := os.Chmod(agent.Path, os.FileMode(agent.Mode).Perm()); err != nil {
						return false, changed, err
					}
				}
				continue
			}
		}
		if !ownInstallFileMatches(agent.Path, pristine) {
			changed = append(changed, agent.Path)
			continue
		}
		if err := writeOwnInstallFile(agent.Path, agent.Data, os.FileMode(agent.Mode).Perm()); err != nil {
			return false, changed, err
		}
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return true, changed, err
	}
	return true, changed, nil
}

// loadOwnInstallSnapshot reads dataDir's snapshot; found is false when there
// is none.
func loadOwnInstallSnapshot(dataDir string) (snapshot ownInstallSnapshot, found bool, err error) {
	path := filepath.Join(dataDir, OwnInstallSnapshotName)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return snapshot, false, nil
	}
	if err != nil {
		return snapshot, false, err
	}
	if !info.Mode().IsRegular() {
		return snapshot, false, fmt.Errorf("%s is not a regular file", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return snapshot, false, err
	}
	if err := json.Unmarshal(data, &snapshot); err != nil || snapshot.Version != ownInstallSnapshotVersion {
		return snapshot, false, fmt.Errorf("%s is not a snapshot this version reads", path)
	}
	return snapshot, true, nil
}

// OwnInstallRegistrationUnchanged reports whether every agent config in
// paths (the files a connector's teardown would edit) is exactly as the
// account's own install had it when the enrollment began, with at least one
// of them kept: the registration in them is that install's own, which the
// enrollment reused, so the uninstall leaves it in place and only puts the
// install's hook files back (RestoreOwnInstall). A teardown there reverted
// the files to their content from before the own install, or removed the
// own install's Hermes approvals (rel-1-0-6 GAP-0178).
func OwnInstallRegistrationUnchanged(dataDir string, paths []string) bool {
	snapshot, found, err := loadOwnInstallSnapshot(dataDir)
	if err != nil || !found || len(paths) == 0 {
		return false
	}
	kept := map[string]string{}
	for _, agent := range snapshot.Agent {
		kept[filepath.Clean(agent.Path)] = string(agent.Data)
	}
	matched := false
	for _, path := range paths {
		path = filepath.Clean(path)
		want, wasKept := kept[path]
		info, err := os.Lstat(path)
		switch {
		case errors.Is(err, os.ErrNotExist):
			if wasKept {
				return false
			}
		case err != nil, !info.Mode().IsRegular(), !wasKept:
			return false
		default:
			data, err := os.ReadFile(path)
			if err != nil || string(data) != want {
				return false
			}
			matched = true
		}
	}
	return matched
}

// ownInstallPristineOf is the pristine hash the kept backup record of
// agentPath holds ("missing" for a file the backup found absent).
func ownInstallPristineOf(files []ownInstallSnapshotFile, agentPath string) (string, bool) {
	for _, file := range files {
		if record, ok := ownInstallBackupRecord(file); ok && record.Path == agentPath {
			if !record.Existed {
				return "missing", true
			}
			return record.PristineSHA256, record.PristineSHA256 != ""
		}
	}
	return "", false
}

// ownInstallFileMatches reports whether path has the content of hash
// ("missing": path does not exist).
func ownInstallFileMatches(path, hash string) bool {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return hash == "missing"
	}
	if err != nil {
		return false
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]) == hash
}

// writeOwnInstallFile replaces path with data and mode through a temporary
// file in the same folder; a link at path is replaced, never followed.
func writeOwnInstallFile(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".restore-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
