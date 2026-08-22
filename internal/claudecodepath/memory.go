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

package claudecodepath

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

const settingsReadLimit = 1024 * 1024

// AutoMemoryResolution describes the best passive resolution of Claude Code's
// project auto-memory location. ActivationVerified is deliberately false:
// session --settings and remote/native managed policy are not visible on disk.
type AutoMemoryResolution struct {
	Path               string
	Source             string
	ProjectRoot        string
	ActivationVerified bool
	Limitation         string
}

// ResolveAutoMemory applies file-based settings precedence and falls back to
// Claude Code's project-derived default. managedPaths is an explicit highest-
// precedence file chain; nil selects the platform's managed-settings files.
func ResolveAutoMemory(configDir, workspace string, managedPaths []string) AutoMemoryResolution {
	workspace = absoluteClean(workspace)
	if workspace == "" {
		return AutoMemoryResolution{
			Limitation: "Claude auto-memory project identity is unresolved because no connector workspace/session CWD is available",
		}
	}
	projectRoot, projectLimitation := resolveProjectRoot(workspace)
	if projectRoot == "" {
		return AutoMemoryResolution{Limitation: projectLimitation}
	}
	if managedPaths == nil {
		managedPaths = defaultManagedSettingsPaths()
	}
	sources := []string{
		filepath.Join(configDir, "settings.json"),
		filepath.Join(projectRoot, ".claude", "settings.json"),
		filepath.Join(projectRoot, ".claude", "settings.local.json"),
	}
	sources = append(sources, managedPaths...)

	var (
		override       string
		overrideSource string
		limitations    []string
	)
	if projectLimitation != "" {
		limitations = append(limitations, projectLimitation)
	}
	for _, source := range sources {
		document, present, err := readJSONFileStable(source)
		if err != nil {
			limitations = append(limitations, err.Error())
			continue
		}
		if !present {
			continue
		}
		if containsPath(managedPaths, source) {
			if helper, ok := document["policyHelper"]; ok && helper != nil {
				limitations = append(limitations,
					fmt.Sprintf("%s configures policyHelper; dynamic managed settings cannot be resolved by passive inventory", source))
			}
		}
		value, exists := document["autoMemoryDirectory"]
		if !exists {
			continue
		}
		text, ok := value.(string)
		if !ok {
			limitations = append(limitations,
				fmt.Sprintf("%s has non-string autoMemoryDirectory and cannot establish an effective memory path", source))
			continue
		}
		candidate, ok := expandMemoryPath(text)
		if !ok {
			limitations = append(limitations,
				fmt.Sprintf("%s has non-absolute autoMemoryDirectory; Claude requires an absolute path or ~/ prefix", source))
			continue
		}
		override = candidate
		overrideSource = source
	}

	path := override
	source := overrideSource
	if path == "" {
		key := projectStorageKey(projectRoot)
		if key == "" {
			return AutoMemoryResolution{
				ProjectRoot: projectRoot,
				Limitation:  "Claude auto-memory project storage identity could not be derived",
			}
		}
		path = filepath.Join(configDir, "projects", key, "memory")
		source = "derived-project-default"
	}
	limitations = append(limitations,
		"passive inventory cannot observe session --settings, remote managed settings, or native registry/MDM policy; confirm the active path with Claude Code /memory or /status")
	return AutoMemoryResolution{
		Path:               filepath.Clean(path),
		Source:             source,
		ProjectRoot:        projectRoot,
		ActivationVerified: false,
		Limitation:         strings.Join(limitations, "; "),
	}
}

// AutoMemoryFiles returns bounded, recursive regular Markdown files below the
// resolved memory directory without following links or reparse points.
func AutoMemoryFiles(resolution AutoMemoryResolution) []string {
	return markdownFiles(resolution.Path)
}

func resolveProjectRoot(workspace string) (string, string) {
	root := repositoryRoot(workspace)
	if root == "" {
		return workspace, "workspace is outside a discoverable Git repository; Claude's documented outside-repository project-root identity is assumed to be the explicit connector workspace"
	}
	marker := filepath.Join(root, ".git")
	info, err := os.Lstat(marker)
	if err != nil {
		return root, fmt.Sprintf("cannot inspect Git project marker %s: %v", marker, err)
	}
	if info.IsDir() {
		return root, ""
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Sprintf("Git project marker %s is not a stable regular file", marker)
	}
	markerBody, err := readStableFile(marker, 8192)
	if err != nil {
		return "", err.Error()
	}
	const prefix = "gitdir:"
	text := strings.TrimSpace(string(markerBody))
	if !strings.HasPrefix(strings.ToLower(text), prefix) {
		return "", fmt.Sprintf("Git project marker %s has an unsupported format", marker)
	}
	gitDir := strings.TrimSpace(text[len(prefix):])
	if !filepath.IsAbs(gitDir) {
		gitDir = filepath.Join(root, gitDir)
	}
	gitDir = filepath.Clean(gitDir)
	commonPath := filepath.Join(gitDir, "commondir")
	commonBody, err := readStableFile(commonPath, 8192)
	if err != nil {
		return root, fmt.Sprintf("linked-worktree project identity is unresolved: %v", err)
	}
	commonDir := strings.TrimSpace(string(commonBody))
	if commonDir == "" {
		return root, fmt.Sprintf("linked-worktree project identity is unresolved: %s is empty", commonPath)
	}
	if !filepath.IsAbs(commonDir) {
		commonDir = filepath.Join(gitDir, commonDir)
	}
	commonDir = filepath.Clean(commonDir)
	if !strings.EqualFold(filepath.Base(commonDir), ".git") {
		return root, fmt.Sprintf("linked-worktree common Git directory does not identify a main checkout root: %s", commonDir)
	}
	return filepath.Dir(commonDir), ""
}

func projectStorageKey(projectRoot string) string {
	var key strings.Builder
	for _, char := range filepath.Clean(projectRoot) {
		switch {
		case char >= 'A' && char <= 'Z',
			char >= 'a' && char <= 'z',
			char >= '0' && char <= '9',
			char == '_', char == '-':
			key.WriteRune(char)
		default:
			key.WriteByte('-')
		}
	}
	return key.String()
}

func expandMemoryPath(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "~/") || strings.HasPrefix(value, `~\`) {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return "", false
		}
		value = filepath.Join(home, strings.TrimLeft(value[1:], `/\`))
	}
	if !filepath.IsAbs(value) {
		return "", false
	}
	return filepath.Clean(value), true
}

func defaultManagedSettingsPaths() []string {
	parent := "/etc/claude-code"
	switch runtime.GOOS {
	case "windows":
		programFiles := strings.TrimSpace(os.Getenv("ProgramFiles"))
		if programFiles == "" {
			programFiles = `C:\Program Files`
		}
		parent = filepath.Join(programFiles, "ClaudeCode")
	case "darwin":
		parent = "/Library/Application Support/ClaudeCode"
	}
	paths := []string{filepath.Join(parent, "managed-settings.json")}
	dropins := filepath.Join(parent, "managed-settings.d")
	info, err := os.Lstat(dropins)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return paths
	}
	entries, err := os.ReadDir(dropins)
	if err != nil {
		return paths
	}
	sort.Slice(entries, func(i, j int) bool {
		return strings.ToLower(entries[i].Name()) < strings.ToLower(entries[j].Name())
	})
	for _, entry := range entries {
		if len(paths) > 256 || entry.IsDir() || strings.HasPrefix(entry.Name(), ".") ||
			!strings.EqualFold(filepath.Ext(entry.Name()), ".json") {
			continue
		}
		path := filepath.Join(dropins, entry.Name())
		info, err := os.Lstat(path)
		if err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
			paths = append(paths, path)
		}
	}
	return paths
}

func readJSONFileStable(path string) (map[string]any, bool, error) {
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("inspect settings file %s: %w", path, err)
	}
	body, err := readStableFile(path, settingsReadLimit)
	if err != nil {
		return nil, false, err
	}
	var document map[string]any
	if err := json.Unmarshal(body, &document); err != nil {
		return nil, false, fmt.Errorf("settings file %s is invalid JSON: %w", path, err)
	}
	if document == nil {
		return nil, false, fmt.Errorf("settings file %s is not a JSON object", path)
	}
	return document, true, nil
}

func readStableFile(path string, limit int64) ([]byte, error) {
	path = filepath.Clean(path)
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("cannot inspect stable file %s: %w", path, err)
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("stable file %s is not a regular non-link file", path)
	}
	for current := filepath.Dir(path); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return nil, fmt.Errorf("cannot inspect stable parent %s: %w", current, err)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("stable parent %s is not a non-link directory", current)
		}
		parent := filepath.Dir(current)
		if samePath(parent, current) {
			break
		}
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open stable file %s: %w", path, err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, fmt.Errorf("stable file %s changed while opening", path)
	}
	body, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read stable file %s: %w", path, err)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("stable file %s exceeds the %d-byte inventory limit", path, limit)
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, after) {
		return nil, fmt.Errorf("stable file %s changed while reading", path)
	}
	return body, nil
}

func markdownFiles(root string) []string {
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

func containsPath(paths []string, want string) bool {
	for _, path := range paths {
		if samePath(path, want) {
			return true
		}
	}
	return false
}
