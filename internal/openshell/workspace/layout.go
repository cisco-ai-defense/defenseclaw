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

package workspace

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// Everything this package persists lives under the DefenseClaw data dir:
//
//	<data>/snapshots/<name>/snapshot.json   snapshot record
//	<data>/snapshots/<name>/tree/           non-git copy snapshot
//	<data>/snapshots/git/<project-key>.git  shadow git dir shared by a project
//	<data>/sandboxes/<name>/workspace/      mask files and mount state
//	<data>/sandboxes/<name>/copy/           copy-mode record, base.git, pulls
//	<data>/sandboxes/<name>/copy.new-<rnd>/ a copy being staged, swapped in whole
type layout struct {
	dataDir string
}

func newLayout(dataDir string) (layout, error) {
	if dataDir == "" {
		return layout{}, errors.New("workspace: data dir is required")
	}
	abs, err := filepath.Abs(dataDir)
	if err != nil {
		return layout{}, fmt.Errorf("workspace: data dir: %w", err)
	}
	return layout{dataDir: filepath.Clean(abs)}, nil
}

func (l layout) snapshotsRoot() string          { return filepath.Join(l.dataDir, "snapshots") }
func (l layout) snapshotDir(name string) string { return filepath.Join(l.snapshotsRoot(), name) }
func (l layout) snapshotRecord(name string) string {
	return filepath.Join(l.snapshotDir(name), "snapshot.json")
}
func (l layout) plainTree(name string) string { return filepath.Join(l.snapshotDir(name), "tree") }
func (l layout) shadowDir(projectKey string) string {
	return filepath.Join(l.snapshotsRoot(), "git", projectKey+".git")
}
func (l layout) sandboxDir(name string) string {
	return filepath.Join(l.dataDir, "sandboxes", name)
}
func (l layout) workspaceDir(name string) string {
	return filepath.Join(l.sandboxDir(name), "workspace")
}
func (l layout) maskDir(name string) string { return filepath.Join(l.workspaceDir(name), "masks") }
func (l layout) mountState(name string) string {
	return filepath.Join(l.workspaceDir(name), "mount.json")
}

// ensurePrivateDir creates dir (and parents) owner-only.
func ensurePrivateDir(dir string) error {
	if err := safefile.ProtectDirectory(dir); err != nil {
		return fmt.Errorf("workspace: prepare %s: %w", dir, err)
	}
	return nil
}

const maxRecordBytes = 64 << 20

func writeJSON(path string, v any) error {
	if err := ensurePrivateDir(filepath.Dir(path)); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("workspace: encode %s: %w", filepath.Base(path), err)
	}
	if err := safefile.Write(path, append(data, '\n')); err != nil {
		return fmt.Errorf("workspace: write %s: %w", path, err)
	}
	return nil
}

func readJSON(path string, v any) error {
	data, err := safefile.ReadRegularFileBounded(path, maxRecordBytes)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return fmt.Errorf("workspace: read %s: %w", path, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("workspace: decode %s: %w", path, err)
	}
	return nil
}

func pathExists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}
