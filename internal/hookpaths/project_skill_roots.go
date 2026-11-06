// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/assetfacts"
)

// ProjectSkillHookCall names the managed Windows hook events that need the
// calling user's project-root inspection beyond session start. The common
// command path keeps its existing Windows cost.
func ProjectSkillHookCall(connector string, payload []byte) bool {
	connector = strings.ToLower(strings.TrimSpace(connector))
	if connector != "claudecode" && connector != "codex" {
		return false
	}
	var event struct {
		ToolName string `json:"tool_name"`
		Prompt   string `json:"prompt"`
	}
	if json.Unmarshal(payload, &event) != nil {
		return false
	}
	switch connector {
	case "claudecode":
		return strings.EqualFold(strings.TrimSpace(event.ToolName), "Skill")
	case "codex":
		return CodexSelectedSkillName(event.Prompt) != ""
	default:
		return false
	}
}

// CodexSelectedSkillName returns the exact first-token skill selection used
// by the Codex prompt hook.
func CodexSelectedSkillName(prompt string) string {
	fields := strings.Fields(strings.TrimSpace(prompt))
	if len(fields) == 0 || !strings.HasPrefix(fields[0], "$") {
		return ""
	}
	name := strings.TrimPrefix(fields[0], "$")
	if name == "" || len(name) > 255 {
		return ""
	}
	for i, r := range name {
		alphaNumeric := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
		if !alphaNumeric && (i == 0 || r != '-' && r != '_' && r != '.') {
			return ""
		}
	}
	return name
}

func projectSkillCallName(raw json.RawMessage) string {
	var values map[string]json.RawMessage
	if json.Unmarshal(raw, &values) != nil {
		return ""
	}
	for _, key := range []string{"skill_name", "skillName", "skill_key", "skillKey", "skill_id", "skillId"} {
		var name string
		if json.Unmarshal(values[key], &name) == nil && projectSkillName(name) != "" {
			return projectSkillName(name)
		}
	}
	for _, key := range []string{"skill", "skill_info", "skillInfo", "source_skill", "sourceSkill"} {
		var name string
		if json.Unmarshal(values[key], &name) == nil && projectSkillName(name) != "" {
			return projectSkillName(name)
		}
		var nested map[string]json.RawMessage
		if json.Unmarshal(values[key], &nested) != nil {
			continue
		}
		for _, field := range []string{"name", "key", "id", "skill_name", "skillName", "skill_key", "skillKey", "skill_id", "skillId"} {
			if json.Unmarshal(nested[field], &name) == nil && projectSkillName(name) != "" {
				return projectSkillName(name)
			}
		}
	}
	return ""
}

// projectSkillCallPath reads the explicit source fields recognized by the
// gateway's Skill probe. An empty result is a name-only selection.
func projectSkillCallPath(raw json.RawMessage) string {
	var values map[string]json.RawMessage
	if json.Unmarshal(raw, &values) != nil {
		return ""
	}
	for _, key := range []string{"skill_path", "skillPath", "source_path", "sourcePath"} {
		var path string
		if json.Unmarshal(values[key], &path) == nil && strings.TrimSpace(path) != "" {
			return path
		}
	}
	for _, key := range []string{"skill", "skill_info", "skillInfo", "source_skill", "sourceSkill"} {
		var value string
		if json.Unmarshal(values[key], &value) == nil && strings.ContainsAny(value, `/\\`) {
			return value
		}
		var nested map[string]json.RawMessage
		if json.Unmarshal(values[key], &nested) != nil {
			continue
		}
		for _, field := range []string{"path", "source_path", "sourcePath", "skill_path", "skillPath"} {
			var path string
			if json.Unmarshal(nested[field], &path) == nil && strings.TrimSpace(path) != "" {
				return path
			}
		}
	}
	return ""
}

func projectSkillName(raw string) string {
	name := strings.TrimPrefix(strings.Trim(strings.TrimSpace(raw), `"'`), "@")
	if name == "" || name == "." || name == ".." || len(name) > 255 || strings.ContainsAny(name, `/\:`) {
		return ""
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return ""
		}
	}
	return name
}

const maxProjectSelectedScan = 4096

func projectSkillSelectedFolders(root, name string) []string {
	direct := filepath.Join(root, name)
	if info, err := os.Stat(filepath.Join(direct, "SKILL.md")); err == nil && info.Mode().IsRegular() {
		return []string{direct}
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return []string{direct}
	}
	for i, entry := range entries {
		if i >= maxProjectSelectedScan {
			return []string{direct}
		}
		if strings.EqualFold(entry.Name(), name) || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		dir := filepath.Join(root, entry.Name())
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			continue
		}
		if strings.EqualFold(assetfacts.DeclaredSkillName(dir), name) {
			return []string{dir}
		}
	}
	return nil
}

// projectSkillSelectionMatchesPath binds a caller-inspected folder to an
// explicit Skill source before the gateway receives the selected-folder fact.
// The caller can resolve a profile link that a managed gateway cannot read.
func projectSkillSelectionMatchesPath(root, selected, source, cwd string) bool {
	if strings.TrimSpace(source) == "" {
		return true
	}
	if !filepath.IsAbs(source) {
		if !filepath.IsAbs(cwd) {
			return false
		}
		source = filepath.Join(cwd, source)
	}
	if projectSkillRootKey(source) == projectSkillRootKey(root) ||
		projectSkillRootKey(source) == projectSkillRootKey(selected) ||
		projectSkillPathWithin(selected, source) {
		return true
	}
	resolvedSource, sourceErr := filepath.EvalSymlinks(source)
	if sourceErr != nil {
		return false
	}
	resolvedRoot, rootErr := filepath.EvalSymlinks(root)
	if rootErr == nil && (projectSkillRootKey(resolvedSource) == projectSkillRootKey(resolvedRoot) ||
		projectSkillPathWithin(resolvedRoot, resolvedSource)) {
		return true
	}
	resolvedSelected, selectedErr := filepath.EvalSymlinks(selected)
	if selectedErr != nil {
		return false
	}
	return projectSkillRootKey(resolvedSource) == projectSkillRootKey(resolvedSelected) ||
		projectSkillPathWithin(resolvedSelected, resolvedSource)
}

// projectSkillRootFacts reports adverse and positively verified roots. The
// Windows hook runs with the caller's profile access, while the managed
// gateway cannot inspect those paths. Every candidate is checked separately.
func projectSkillRootFacts(connector, home, cwd string) map[string]string {
	if runtime.GOOS != "windows" || !projectSkillPathWithin(home, cwd) {
		return nil
	}
	user := map[string]bool{}
	for _, root := range assetfacts.SkillRoots(connector, home, "") {
		user[projectSkillRootKey(root)] = true
	}
	var facts map[string]string
	for _, root := range assetfacts.SkillRoots(connector, home, cwd) {
		if user[projectSkillRootKey(root)] || !projectSkillPathWithin(home, root) {
			continue
		}
		finding := inspectProjectSkillRoot(home, root)
		if finding == "" {
			if info, err := os.Stat(root); err == nil && info.IsDir() {
				if facts == nil {
					facts = map[string]string{}
				}
				facts[ProjectSkillRootVerifiedPrefix+root] = "1"
			}
			continue
		}
		if facts == nil {
			facts = map[string]string{}
		}
		facts[ProjectSkillRootUnverifiedPrefix+root] = finding
	}
	return facts
}

func projectSkillRootKey(path string) string {
	path = filepath.Clean(path)
	if runtime.GOOS == "windows" {
		path = strings.ToLower(path)
	}
	return path
}

func projectSkillPathWithin(home, path string) bool {
	if !filepath.IsAbs(home) || !filepath.IsAbs(path) {
		return false
	}
	if runtime.GOOS == "windows" {
		home, path = strings.ToLower(home), strings.ToLower(path)
	}
	rel, err := filepath.Rel(filepath.Clean(home), filepath.Clean(path))
	return err == nil && rel != "." && rel != ".." && !filepath.IsAbs(rel) &&
		!strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func inspectProjectSkillRoot(home, root string) string {
	if info, err := os.Lstat(root); errors.Is(err, fs.ErrNotExist) {
		return ""
	} else if err != nil {
		return ProjectSkillRootUnreadable
	} else if !info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
		return ""
	}
	realHome, err := filepath.EvalSymlinks(home)
	if err != nil {
		return ProjectSkillRootUnreadable
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if errors.Is(err, fs.ErrNotExist) {
		return ""
	} else if err != nil {
		return ProjectSkillRootUnreadable
	}
	info, err := os.Stat(realRoot)
	if errors.Is(err, fs.ErrNotExist) || err == nil && !info.IsDir() {
		return ""
	} else if err != nil {
		return ProjectSkillRootUnreadable
	}
	if !projectSkillPathWithin(realHome, realRoot) {
		return ProjectSkillRootOutsideProfile
	}
	shared, err := projectSkillRootSharedWritable(realHome, realRoot)
	if err != nil {
		return ProjectSkillRootUnreadable
	}
	if shared {
		return ProjectSkillRootSharedWritable
	}
	if projectSkillRootKey(realHome) == projectSkillRootKey(home) &&
		projectSkillRootKey(realRoot) == projectSkillRootKey(root) {
		return ""
	}
	// The physical target may be private while a folder on the lexical
	// project path is replaceable by another user. Inspect both chains.
	shared, err = projectSkillRootSharedWritable(home, root)
	if err != nil {
		return ProjectSkillRootUnreadable
	}
	if shared {
		return ProjectSkillRootSharedWritable
	}
	return ""
}
