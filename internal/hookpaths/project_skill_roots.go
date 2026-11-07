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
	"slices"
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

// projectSkillCallSelection reads a Skill call with the gateway parser. The
// name is the one the gateway decides on: the top-level event fields first,
// then the tool input. It is empty when no selected-folder fact can carry
// it. sources lists every explicit source path in either field set, so a
// path the gateway does not read next to that name still decides which
// folder the call selects.
func projectSkillCallSelection(payload, args json.RawMessage) (name string, sources []string) {
	for _, raw := range []json.RawMessage{payload, args} {
		var values map[string]any
		if json.Unmarshal(raw, &values) != nil {
			continue
		}
		selected, path, _ := assetfacts.SkillSelection(values)
		if selected == "" {
			continue
		}
		if name == "" {
			if !projectSkillFactName(selected) {
				return "", nil
			}
			name = selected
		}
		if path != "" && !slices.Contains(sources, path) {
			sources = append(sources, path)
		}
	}
	return name, sources
}

// projectSkillFactName reports whether name can be a selected-folder fact
// value: a name the shared selection parser returns, within the path bound.
// It need not be a folder name; an explicit source binds the folder.
func projectSkillFactName(name string) bool {
	return name != "" && len(name) <= MaxWriteTargetPathBytes && assetfacts.SkillRuntimeName(name) == name
}

// addProjectSkillSelectedFacts names the folder a Skill call selects under
// each unverified root in facts. Explicit sources bind folders by path; a
// name-only call binds the folder of that name or declared name.
func addProjectSkillSelectedFacts(facts map[string]string, payload, args json.RawMessage, home, cwd string) {
	name, sources := projectSkillCallSelection(payload, args)
	if name == "" {
		return
	}
	roots := make([]string, 0, len(facts))
	for key := range facts {
		if strings.HasPrefix(key, ProjectSkillRootUnverifiedPrefix) {
			roots = append(roots, strings.TrimPrefix(key, ProjectSkillRootUnverifiedPrefix))
		}
	}
	for _, root := range roots {
		var dirs []string
		if len(sources) == 0 {
			dirs = projectSkillSelectedFolders(root, name)
		}
		for _, source := range sources {
			dirs = append(dirs, projectSkillSourceFolders(root, name, source, home, cwd)...)
		}
		for _, dir := range dirs {
			facts[ProjectSkillSelectedPrefix+dir] = name
		}
	}
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

// projectSkillSelectedFolders returns the folder under root that a name-only
// call selects: root/name when it holds a manifest, else the folder whose
// manifest declares name. The lookup reads the whole root as the calling
// user, so it neither invents a project copy nor misses a late folder. When
// the caller cannot list the root, root/name counts only if its manifest
// could not be ruled out; the agent, running as the same user, cannot find
// a declared-name folder there either. A name that is not a folder name
// selects no folder by name, as in the gateway.
func projectSkillSelectedFolders(root, name string) []string {
	if projectSkillName(name) != name {
		return nil
	}
	direct := filepath.Join(root, name)
	info, directErr := os.Stat(filepath.Join(direct, "SKILL.md"))
	if directErr == nil && info.Mode().IsRegular() {
		return []string{direct}
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		if directErr != nil && !errors.Is(directErr, fs.ErrNotExist) {
			return []string{direct}
		}
		return nil
	}
	for _, entry := range entries {
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

// projectSkillSourceFolders returns the folders under an unverified root
// that an explicit Skill source names. The source is compared with the root
// lexically and through the caller's resolved view, which a managed gateway
// cannot inspect, so the result does not depend on the selected name. A
// source naming the root itself selects the root and its named folder.
func projectSkillSourceFolders(root, name, source, home, cwd string) []string {
	if !filepath.IsAbs(source) {
		if !filepath.IsAbs(cwd) {
			return nil
		}
		source = filepath.Join(cwd, source)
	}
	source = filepath.Clean(source)
	resolvedSource, sourceErr := filepath.EvalSymlinks(source)
	resolvedRoot, rootErr := filepath.EvalSymlinks(root)
	if projectSkillRootKey(source) == projectSkillRootKey(root) ||
		sourceErr == nil && rootErr == nil && projectSkillRootKey(resolvedSource) == projectSkillRootKey(resolvedRoot) &&
			projectSkillSourceSelects(home, resolvedRoot, resolvedSource) {
		return append(projectSkillSelectedFolders(root, name), root)
	}
	if child := projectSkillChild(root, source); child != "" {
		return []string{filepath.Join(root, child)}
	}
	if sourceErr != nil {
		return nil
	}
	if rootErr == nil {
		if child := projectSkillChild(resolvedRoot, resolvedSource); child != "" &&
			projectSkillSourceSelects(home, filepath.Join(resolvedRoot, child), resolvedSource) {
			return []string{filepath.Join(root, child)}
		}
	}
	// A folder under the root may itself be a link or other reparse point
	// to the source. A plain folder or file resolves under the resolved root,
	// which the checks above cover, so only the other entries are resolved,
	// all of them.
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	for _, entry := range entries {
		if kind := entry.Type(); kind == 0 || kind == fs.ModeDir {
			continue
		}
		dir := filepath.Join(root, entry.Name())
		resolved, err := filepath.EvalSymlinks(dir)
		if err == nil && projectSkillSourceSelects(home, resolved, resolvedSource) {
			return []string{dir}
		}
	}
	return nil
}

// projectSkillSourceSelects reports whether a resolved source selects the
// resolved project folder: the source is the folder, its manifest or a path
// in it that no other skill folder owns. The nearest skill folder holding the
// source, the project folder itself included, is its owner. When the caller
// profile holds that owner privately, the source is that user skill's own
// selection, whichever way a project link reaches it, so the project folder
// does not claim it. An owner another user can change, or one outside the
// profile, still counts.
func projectSkillSourceSelects(home, folder, source string) bool {
	if projectSkillRootKey(folder) != projectSkillRootKey(source) && !projectSkillPathWithin(folder, source) {
		return false
	}
	// A project link to a skill folder reaches its manifest as a child named
	// SKILL.md. That child is no folder: the folder holding it is the
	// candidate, so its owner is weighed like any other.
	if info, err := os.Stat(folder); err == nil && !info.IsDir() {
		folder = filepath.Dir(folder)
	}
	for dir := source; ; dir = filepath.Dir(dir) {
		if info, err := os.Stat(filepath.Join(dir, "SKILL.md")); err == nil && info.Mode().IsRegular() {
			return !projectSkillPrivateFolder(home, dir)
		}
		if parent := filepath.Dir(dir); projectSkillRootKey(dir) == projectSkillRootKey(folder) || parent == dir {
			return true
		}
	}
}

// projectSkillPrivateFolder reports whether a resolved folder lies in the
// caller's profile with no folder on the way to it writable by another user.
func projectSkillPrivateFolder(home, dir string) bool {
	realHome, err := filepath.EvalSymlinks(home)
	if err != nil || !projectSkillPathWithin(realHome, dir) {
		return false
	}
	shared, err := projectSkillRootSharedWritable(realHome, dir)
	return err == nil && !shared
}

// projectSkillChild names the first folder under root on the way to path.
func projectSkillChild(root, path string) string {
	if !projectSkillPathWithin(root, path) {
		return ""
	}
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(path))
	if err != nil {
		return ""
	}
	return strings.SplitN(rel, string(filepath.Separator), 2)[0]
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
