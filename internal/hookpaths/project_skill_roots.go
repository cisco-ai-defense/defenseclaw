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
	if !strings.EqualFold(strings.TrimSpace(connector), "claudecode") {
		return false
	}
	var event struct {
		ToolName string `json:"tool_name"`
	}
	return json.Unmarshal(payload, &event) == nil && strings.EqualFold(strings.TrimSpace(event.ToolName), "Skill")
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

// projectSkillRootFacts reports only adverse facts. The Windows hook runs
// with the caller's profile access, while the managed gateway cannot inspect
// those paths. Every candidate is independently checked; a safe root adds
// nothing to the header and cannot clear an earlier refusal.
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
