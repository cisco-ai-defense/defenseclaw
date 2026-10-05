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

package watcher

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// claudeSyncedSkillDirs expands Claude Code's account-synced skill container,
// ~/.claude/skills/synced/<account-id>/<skill>/SKILL.md (GAP-1243). The
// "synced" folder is a container, not a skill: scanning it as one failed with
// "SKILL.md not found" on every rescan and hid the real skills below it.
//
// ok is false when path is not that container, so callers keep treating it
// as an ordinary skill directory. Symlinked folders are not followed.
func claudeSyncedSkillDirs(path string) (skills []string, ok bool) {
	clean := filepath.Clean(path)
	root := filepath.Dir(clean)
	if filepath.Base(clean) != "synced" ||
		!strings.EqualFold(filepath.Base(root), "skills") ||
		!strings.EqualFold(filepath.Base(filepath.Dir(root)), ".claude") {
		return nil, false
	}
	if info, err := os.Lstat(clean); err != nil || !info.IsDir() {
		return nil, false
	}
	if hasSkillMarker(clean) {
		return nil, false
	}
	accounts, err := os.ReadDir(clean)
	if err != nil {
		return nil, true
	}
	for _, account := range accounts {
		if !account.IsDir() || strings.HasPrefix(account.Name(), ".") {
			continue
		}
		accountPath := filepath.Join(clean, account.Name())
		children, err := os.ReadDir(accountPath)
		if err != nil {
			continue
		}
		for _, child := range children {
			if !child.IsDir() || strings.HasPrefix(child.Name(), ".") {
				continue
			}
			skillPath := filepath.Join(accountPath, child.Name())
			if hasSkillMarker(skillPath) {
				skills = append(skills, skillPath)
			}
		}
	}
	return skills, true
}

func hasSkillMarker(dir string) bool {
	info, err := os.Lstat(filepath.Join(dir, "SKILL.md"))
	return err == nil && info.Mode().IsRegular()
}

// isClaudeSyncedContainer reports whether path is a real (non-symlink)
// skills/synced folder that is not itself a skill.
func isClaudeSyncedContainer(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.IsDir() && !hasSkillMarker(path)
}

// claudeSyncedDepth places path under a watched .claude/skills/synced
// container: 0 is the container, 1 an account folder, 2 a synced skill
// (GAP-1409). ok is false for any other path.
func (w *InstallWatcher) claudeSyncedDepth(path string) (depth int, ok bool) {
	pathAbs, err := filepath.Abs(path)
	if err != nil {
		return 0, false
	}
	for _, dir := range w.skillDirs {
		dirAbs, absErr := filepath.Abs(dir)
		if absErr != nil || !strings.EqualFold(filepath.Base(dirAbs), "skills") ||
			!strings.EqualFold(filepath.Base(filepath.Dir(dirAbs)), ".claude") {
			continue
		}
		root := filepath.Join(dirAbs, "synced")
		relative, relErr := filepath.Rel(root, pathAbs)
		if relErr != nil || relative == ".." ||
			strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			continue
		}
		if !isClaudeSyncedContainer(root) {
			return 0, false
		}
		if relative == "." {
			return 0, true
		}
		depth = len(strings.FieldsFunc(relative, func(r rune) bool {
			return r == '/' || r == '\\'
		}))
		if depth > 2 {
			return 0, false
		}
		return depth, true
	}
	return 0, false
}

// queueSyncedSkill records a watcher event for a synced skill folder and
// queues it for the debounced admission scan.
func (w *InstallWatcher) queueSyncedSkill(ctx context.Context, path string) {
	w.recordWatcherEvent(ctx, "create", InstallSkill.String(), "")
	w.mu.Lock()
	if _, exists := w.pending[path]; !exists {
		w.pending[path] = time.Now()
	}
	w.mu.Unlock()
}
