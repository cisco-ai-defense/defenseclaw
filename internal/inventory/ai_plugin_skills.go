// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// Plugin skills. Claude Code, Codex, Cursor and the Copilot CLI install
// plugins that ship skills in <plugin>/skills/<name>/SKILL.md, or in the
// folders the plugin manifest names, outside the agents' skill folders.
// Each agent's own record of what is installed picks the plugin folder, so
// old versions left in a plugin cache are not reported.

const maxPluginRegistryBytes = 4 << 20

// AISkillPlugin is the plugin a skill came with.
type AISkillPlugin struct {
	ID      string `json:"id"` // name@marketplace
	Version string `json:"version,omitempty"`
	// Author is the plugin manifest's author name.
	Author  string `json:"author,omitempty"`
	Enabled *bool  `json:"enabled,omitempty"`
}

type installedPlugin struct {
	signature, id, dir, version string
	enabled                     *bool
}

func (s *ContinuousDiscoveryService) detectPluginSkills() []AISignal {
	var out []AISignal
	for _, home := range s.homesToScan() {
		plugins := append(append(claudePlugins(s.agentHome(home, "CLAUDE_CONFIG_DIR")), codexPlugins(s.agentHome(home, "CODEX_HOME"))...),
			copilotPlugins(s.agentHome(home, "COPILOT_HOME"))...)
		for _, plugin := range append(plugins, cursorPlugins(home)...) {
			sig := s.signatureByID(plugin.signature)
			if sig == nil {
				continue
			}
			version, author, folders := pluginManifest(plugin.dir)
			if version == "" {
				version = plugin.version
			}
			// Claude Code adds the manifest's folders to skills/; the other
			// agents load them instead of skills/.
			if len(folders) == 0 || plugin.signature == "claudecode" {
				folders = append([]string{"skills"}, folders...)
			}
			info := &AISkillPlugin{
				ID: plugin.id, Version: pluginText(version, 64), Author: pluginText(author, maxSkillAuthorBytes), Enabled: plugin.enabled,
			}
			seen := map[string]bool{}
			for _, rel := range folders {
				skills := filepath.Join(plugin.dir, rel)
				if seen[rel] || !realDirsBelow(plugin.dir, rel+"/x") || !dirHasEntry(skills) || s.profileLinkRefused(skills) {
					continue
				}
				seen[rel] = true
				identityPath := filepath.Join(home, plugin.signature, "plugins", plugin.id, rel)
				signal := s.signalFromDirectoryChildrenIdentity(*sig, SignalSkill, "skill", skills, identityPath)
				if s.profileLinkRefused(skills) {
					continue // the folder became a link while it was read
				}
				// The plugin, not its version folder, keys these skills, so an
				// upgrade reads as changed rather than removed and added.
				for _, ev := range signal.Evidence {
					if ev.Skill != nil {
						ev.Skill.Scope, ev.Skill.Plugin = SkillScopePlugin, info
					}
				}
				signal.EvidenceHash = hashEvidence(signal.Evidence)
				out = append(out, signal)
			}
		}
	}
	return out
}

func (s *ContinuousDiscoveryService) signatureByID(id string) *AISignature {
	for i := range s.catalog {
		if s.catalog[i].ID == id {
			return &s.catalog[i]
		}
	}
	return nil
}

// claudePlugins reads plugins/installed_plugins.json and enabledPlugins in
// the Claude Code folder dir.
func claudePlugins(dir string) []installedPlugin {
	root := filepath.Join(dir, "plugins")
	var registry struct {
		Plugins map[string]json.RawMessage `json:"plugins"`
	}
	if !readPluginJSON(filepath.Join(root, "installed_plugins.json"), &registry) {
		return nil
	}
	var settings struct {
		EnabledPlugins map[string]bool `json:"enabledPlugins"`
	}
	readPluginJSON(filepath.Join(dir, "settings.json"), &settings)
	var out []installedPlugin
	seen := map[string]bool{}
	for id, raw := range registry.Plugins {
		type install struct {
			InstallPath string `json:"installPath"`
			Version     string `json:"version"`
		}
		var records []install
		if json.Unmarshal(raw, &records) != nil {
			var one install // the single-record form of older registries
			if json.Unmarshal(raw, &one) != nil {
				continue
			}
			records = []install{one}
		}
		for _, record := range records {
			dir := filepath.Clean(record.InstallPath)
			if !pathBelow(filepath.Join(root, "cache"), dir) || seen[dir] || !validPluginID(id) {
				continue
			}
			seen[dir] = true
			plugin := installedPlugin{signature: "claudecode", id: id, dir: dir, version: record.Version}
			if enabled, ok := settings.EnabledPlugins[id]; ok {
				plugin.enabled = &enabled
			}
			out = append(out, plugin)
		}
	}
	return out
}

// codexPlugins reads [plugins."name@marketplace"] from config.toml; the
// newest folder in plugins/cache/<marketplace>/<name> is the installed copy.
func codexPlugins(codexHome string) []installedPlugin {
	data, err := safefile.ReadRegularFileBounded(filepath.Join(codexHome, "config.toml"), maxPluginRegistryBytes)
	var config struct {
		Plugins map[string]struct {
			Enabled *bool `toml:"enabled"`
		} `toml:"plugins"`
	}
	if err != nil || toml.Unmarshal(data, &config) != nil {
		return nil
	}
	var out []installedPlugin
	for id, entry := range config.Plugins {
		name, marketplace, _ := strings.Cut(id, "@")
		if !validPluginID(id) {
			continue
		}
		if dir := newestChildDir(filepath.Join(codexHome, "plugins", "cache", marketplace, name), ""); dir != "" {
			out = append(out, installedPlugin{signature: "codex", id: id, dir: dir, version: filepath.Base(dir), enabled: entry.Enabled})
		}
	}
	return out
}

// copilotPlugins lists installed-plugins/<marketplace>/<plugin>.
func copilotPlugins(copilotHome string) []installedPlugin {
	root := filepath.Join(copilotHome, "installed-plugins")
	var out []installedPlugin
	for _, marketplace := range realChildDirs(root) {
		for _, dir := range realChildDirs(filepath.Join(root, marketplace)) {
			if id := dir + "@" + marketplace; validPluginID(id) {
				out = append(out, installedPlugin{signature: "copilot", id: id, dir: filepath.Join(root, marketplace, dir)})
			}
		}
	}
	return out
}

// cursorPlugins lists plugins/cache/<marketplace>/<plugin>/<commit>, the
// newest complete copy, and plugins/local/<plugin>. Cursor keeps no
// enabled flag on disk.
func cursorPlugins(home string) []installedPlugin {
	root := filepath.Join(home, ".cursor", "plugins")
	var out []installedPlugin
	for _, marketplace := range realChildDirs(filepath.Join(root, "cache")) {
		for _, name := range realChildDirs(filepath.Join(root, "cache", marketplace)) {
			id := name + "@" + marketplace
			if dir := newestChildDir(filepath.Join(root, "cache", marketplace, name), ".cache-complete"); dir != "" && validPluginID(id) {
				out = append(out, installedPlugin{signature: "cursor", id: id, dir: dir})
			}
		}
	}
	for _, name := range realChildDirs(filepath.Join(root, "local")) {
		if id := name + "@local"; validPluginID(id) {
			out = append(out, installedPlugin{signature: "cursor", id: id, dir: filepath.Join(root, "local", name)})
		}
	}
	return out
}

// pluginManifest returns the version, author name and skill folders a
// plugin manifest declares, from the first manifest the agents document.
// Skill folders outside the plugin are dropped.
func pluginManifest(dir string) (version, author string, skills []string) {
	for _, rel := range []string{".claude-plugin/plugin.json", ".codex-plugin/plugin.json", ".cursor-plugin/plugin.json", "plugin.json", ".plugin/plugin.json", ".github/plugin/plugin.json"} {
		var manifest struct {
			Version string          `json:"version"`
			Author  json.RawMessage `json:"author"`
			Skills  json.RawMessage `json:"skills"`
		}
		if !realDirsBelow(dir, rel) || !readPluginJSON(filepath.Join(dir, filepath.FromSlash(rel)), &manifest) {
			continue
		}
		var named struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(manifest.Author, &named) != nil {
			_ = json.Unmarshal(manifest.Author, &named.Name)
		}
		var paths []string
		if json.Unmarshal(manifest.Skills, &paths) != nil {
			var one string
			_ = json.Unmarshal(manifest.Skills, &one)
			paths = []string{one}
		}
		for _, path := range paths {
			if clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(path))); path != "" && len(skills) < 16 && pathBelow(dir, filepath.Join(dir, clean)) {
				skills = append(skills, clean)
			}
		}
		return manifest.Version, named.Name, skills
	}
	return "", "", nil
}

// realDirsBelow reports whether every folder between dir and rel's file is
// a real folder, not a link or junction out of the plugin.
func realDirsBelow(dir, rel string) bool {
	for parent := filepath.Dir(filepath.FromSlash(rel)); parent != "."; parent = filepath.Dir(parent) {
		if info, err := os.Lstat(filepath.Join(dir, parent)); err != nil || !info.IsDir() {
			return false
		}
	}
	return true
}

func readPluginJSON(path string, into any) bool {
	data, err := safefile.ReadRegularFileBounded(path, maxPluginRegistryBytes)
	return err == nil && json.Unmarshal(data, into) == nil
}

func validPluginID(id string) bool {
	name, marketplace, ok := strings.Cut(id, "@")
	return ok && sanitizeBasenameValue(name) == name && sanitizeBasenameValue(marketplace) == marketplace &&
		name != "." && name != ".." && marketplace != "." && marketplace != ".." && len(id) <= 256
}

func pathBelow(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != "." && rel != ".." && !filepath.IsAbs(rel) &&
		!strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// newestChildDir is the newest folder in dir that holds the marker file,
// when one is named.
func newestChildDir(dir, marker string) string {
	newest, newestAt := "", int64(0)
	for _, name := range realChildDirs(dir) {
		if marker != "" {
			if info, err := os.Lstat(filepath.Join(dir, name, marker)); err != nil || !info.Mode().IsRegular() {
				continue
			}
		}
		info, err := os.Lstat(filepath.Join(dir, name))
		if err == nil && info.ModTime().UnixNano() > newestAt {
			newest, newestAt = filepath.Join(dir, name), info.ModTime().UnixNano()
		}
	}
	return newest
}

func pluginText(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) > limit || containsUnicodeControl(value) {
		return ""
	}
	return value
}
