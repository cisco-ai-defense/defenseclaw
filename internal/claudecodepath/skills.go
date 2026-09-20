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

// Package claudecodepath owns Claude Code's project component-root model.
package claudecodepath

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// discoveryDirLimit bounds passive nested-root discovery in attacker-controlled
// repositories while covering ordinary monorepos deterministically.
const discoveryDirLimit = 32768

// ProjectSkillDirs returns the documented Claude Code project skill roots for
// a launch directory: the launch directory and each parent through the nearest
// repository root, plus existing nested .claude/skills roots below the launch
// directory that Claude can lazily activate after file activity.
func ProjectSkillDirs(launchDir string) []string {
	start := absoluteClean(launchDir)
	if start == "" {
		return nil
	}

	roots := make([]string, 0, 8)
	for _, current := range projectAncestorDirs(start) {
		roots = append(roots, filepath.Join(current, ".claude", "skills"))
	}

	visited := 0
	_ = filepath.WalkDir(start, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			if entry != nil && entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !entry.IsDir() {
			return nil
		}
		if entry.Name() == ".git" && !samePath(path, start) {
			return filepath.SkipDir
		}
		visited++
		if visited > discoveryDirLimit {
			return filepath.SkipAll
		}
		if strings.EqualFold(entry.Name(), "skills") &&
			strings.EqualFold(filepath.Base(filepath.Dir(path)), ".claude") {
			roots = append(roots, filepath.Clean(path))
		}
		return nil
	})
	return uniquePaths(roots)
}

// SkillDirs resolves the immediate skill-name entries Claude Code loads from
// one skills root. Claude v2.1.203+ follows directory symlinks and de-duplicates
// aliases to the same target, so this resolver intentionally follows only that
// documented component boundary and returns canonical target directories.
func SkillDirs(root string) []string {
	root = absoluteClean(root)
	if root == "" {
		return nil
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	if len(entries) > discoveryDirLimit {
		entries = entries[:discoveryDirLimit]
	}
	dirs := make([]string, 0, len(entries))
	for _, entry := range entries {
		path := filepath.Join(root, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			continue
		}
		resolved := path
		if info.Mode()&os.ModeSymlink != 0 {
			resolved, err = filepath.EvalSymlinks(path)
			if err != nil {
				continue
			}
			resolved, err = filepath.Abs(resolved)
			if err != nil {
				continue
			}
			info, err = os.Stat(resolved)
			if err != nil {
				continue
			}
		}
		if !info.IsDir() {
			continue
		}
		dirs = append(dirs, filepath.Clean(resolved))
	}
	return uniquePaths(dirs)
}

// ProjectAgentDirs returns each project-level .claude/agents directory from
// the launch directory through the nearest repository root, ordered closest
// first to match Claude Code's documented nested-project precedence.
func ProjectAgentDirs(launchDir string) []string {
	start := absoluteClean(launchDir)
	if start == "" {
		return nil
	}
	roots := make([]string, 0, 8)
	for _, current := range projectAncestorDirs(start) {
		roots = append(roots, filepath.Join(current, ".claude", "agents"))
	}
	return uniquePaths(roots)
}

// AgentFiles recursively enumerates regular Markdown definitions below an
// agent root without following links or reparse points. Identity is defined by
// YAML frontmatter rather than the filename; semantic inventory validates it.
func AgentFiles(root string) []string {
	root = absoluteClean(root)
	if root == "" {
		return nil
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil
	}

	files := make([]string, 0, 8)
	visited := 0
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			if entry != nil && entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			visited++
			if visited > discoveryDirLimit {
				return filepath.SkipAll
			}
			if path != root {
				info, err := entry.Info()
				if err != nil || info.Mode()&os.ModeSymlink != 0 {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.EqualFold(filepath.Ext(entry.Name()), ".md") {
			return nil
		}
		info, err := entry.Info()
		if err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
			files = append(files, filepath.Clean(path))
		}
		return nil
	})
	return uniquePaths(files)
}

func projectAncestorDirs(start string) []string {
	repoRoot := repositoryRoot(start)
	roots := make([]string, 0, 8)
	for current := start; ; current = filepath.Dir(current) {
		roots = append(roots, current)
		if repoRoot == "" || samePath(current, repoRoot) {
			break
		}
		parent := filepath.Dir(current)
		if samePath(parent, current) {
			break
		}
	}
	return roots
}

func repositoryRoot(start string) string {
	for current := start; ; current = filepath.Dir(current) {
		if info, err := os.Lstat(filepath.Join(current, ".git")); err == nil &&
			(info.IsDir() || info.Mode().IsRegular()) {
			return current
		}
		parent := filepath.Dir(current)
		if samePath(parent, current) {
			return ""
		}
	}
}

func absoluteClean(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return ""
	}
	return filepath.Clean(absolute)
}

func samePath(left, right string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(filepath.Clean(left), filepath.Clean(right))
	}
	return filepath.Clean(left) == filepath.Clean(right)
}

func uniquePaths(paths []string) []string {
	out := make([]string, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		key := filepath.Clean(path)
		if runtime.GOOS == "windows" {
			key = strings.ToLower(key)
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, filepath.Clean(path))
	}
	return out
}
