// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Claude Code plugins enabled through enabledPlugins in user or project
// settings ship their own hooks (hooks/hooks.json, or a hooks entry in
// .claude-plugin/plugin.json) that can return updatedInput. When the
// administrator relaxes Claude's managed-hooks-only lock the guard covers
// Claude, so those hooks are scanned like any other foreign hook. Installed
// plugins are found through Claude's plugin registry
// (<config dir>/plugins/installed_plugins.json); an enabled plugin that is
// not installed cannot run and is skipped, while a registry or plugin that
// cannot be read fails closed.

// claudePluginRegistryLimit bounds installed_plugins.json.
const claudePluginRegistryLimit = 4 << 20

func (s *guardScan) scanClaudePlugins(source hookSource) []Finding {
	req := s.req
	data, exists, err := s.readSource(source)
	if err != nil || !exists {
		// The settings file's own source reports a read failure.
		return nil
	}
	doc, _, err := decodeGuardDocument(data)
	if err != nil {
		return nil
	}
	enabledValue, _ := doc.get("enabledPlugins")
	enabledObject, _ := enabledValue.(*object)
	if enabledObject == nil {
		return nil
	}
	var enabled []string
	for _, id := range enabledObject.keys {
		if value, _ := enabledObject.get(id); value == true {
			enabled = append(enabled, id)
		}
	}
	if len(enabled) == 0 {
		return nil
	}
	claudeDir := req.getenv("CLAUDE_CONFIG_DIR")
	if claudeDir == "" {
		if source.home == "" {
			return []Finding{unreadableFinding(req, source, errors.New("plugins are enabled but the Claude config directory is unknown"))}
		}
		claudeDir = filepath.Join(source.home, ".claude")
	}
	registrySource := source.child(filepath.Join(claudeDir, "plugins", "installed_plugins.json"), formatClaudePlugins)
	registryData, exists, err := s.readFileLimit(registrySource.path, claudePluginRegistryLimit)
	if err != nil {
		return []Finding{s.unreadable(registrySource, err)}
	}
	if !exists {
		return nil
	}
	installs, err := claudePluginInstallPaths(registryData)
	if err != nil {
		return []Finding{s.unreadable(registrySource, err)}
	}
	var findings []Finding
	for _, id := range enabled {
		for _, root := range installs[id] {
			findings = append(findings, s.scanClaudePluginRoot(source, id, root)...)
			if s.exceeded != nil {
				return findings
			}
		}
	}
	return findings
}

// claudePluginInstallPaths reads installed_plugins.json: version 1 maps a
// plugin id to one install record, version 2 to a list of records (one per
// scope); each record carries installPath.
func claudePluginInstallPaths(data []byte) (map[string][]string, error) {
	doc, _, err := decodeGuardDocument(data)
	if err != nil {
		return nil, fmt.Errorf("decode Claude plugin registry: %w", err)
	}
	pluginsValue, _ := doc.get("plugins")
	plugins, ok := pluginsValue.(*object)
	if !ok {
		if pluginsValue == nil {
			return map[string][]string{}, nil
		}
		return nil, errors.New("Claude plugin registry has no plugins object")
	}
	out := map[string][]string{}
	for _, id := range plugins.keys {
		value, _ := plugins.get(id)
		records := []any{value}
		if list, ok := value.([]any); ok {
			records = list
		}
		for _, record := range records {
			path := strings.TrimSpace(stringField(record, "installPath"))
			if path == "" {
				return nil, fmt.Errorf("Claude plugin registry entry %s has no installPath", id)
			}
			out[id] = append(out[id], path)
		}
		sort.Strings(out[id])
	}
	return out, nil
}

// scanClaudePluginRoot scans one installed plugin's hook files.
func (s *guardScan) scanClaudePluginRoot(enabling hookSource, id, root string) []Finding {
	req := s.req
	rootSource := enabling.child(root, formatClaudePlugins)
	if !filepath.IsAbs(root) {
		return []Finding{unreadableFinding(req, rootSource, fmt.Errorf("plugin %s has a relative install path", id))}
	}
	root = filepath.Clean(root)
	info, err := os.Lstat(root)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil
	case err != nil:
		return []Finding{s.unreadable(rootSource, err)}
	case info.Mode()&os.ModeSymlink != 0:
		return []Finding{unreadableFinding(req, rootSource, fmt.Errorf("plugin %s install path is a symbolic link", id))}
	case !info.IsDir():
		return []Finding{unreadableFinding(req, rootSource, fmt.Errorf("plugin %s install path is not a directory", id))}
	}
	return s.scanPluginHooks(enabling, root, []string{filepath.Join(".claude-plugin", "plugin.json")}, []string{filepath.Join("hooks", "hooks.json")}, formatGrouped)
}

// scanPluginHooks scans one plugin root's hook files: the default files
// (relative to root) and whatever the first existing manifest's hooks entry
// names (a path, a list of paths, or inline hooks). format is the hook file
// format.
func (s *guardScan) scanPluginHooks(enabling hookSource, root string, manifests, defaults []string, format string) []Finding {
	req := s.req
	pluginSource := func(path string) hookSource {
		return hookSource{scope: enabling.scope, path: path, format: format, base: root, home: enabling.home}
	}
	var files []string
	for _, rel := range defaults {
		files = append(files, filepath.Join(root, rel))
	}
	var findings []Finding
	for _, rel := range manifests {
		manifestSource := pluginSource(filepath.Join(root, rel))
		manifest, exists, err := s.readFile(manifestSource.path)
		if err != nil {
			return []Finding{s.unreadable(manifestSource, err)}
		}
		if !exists {
			continue
		}
		doc, _, err := decodeGuardDocument(manifest)
		if err != nil {
			return []Finding{s.unreadable(manifestSource, err)}
		}
		hooksValue, _ := doc.get("hooks")
		switch v := hooksValue.(type) {
		case nil:
		case string:
			files = append(files, filepath.Join(root, filepath.FromSlash(v)))
		case []any:
			for _, item := range v {
				path, ok := item.(string)
				if !ok {
					return []Finding{unreadableFinding(req, manifestSource, errors.New("plugin manifest hooks list holds a non-string entry"))}
				}
				files = append(files, filepath.Join(root, filepath.FromSlash(path)))
			}
		case *object:
			// Inline hooks: either a hooks document or the hooks map itself.
			inline := v
			if _, nested := v.get("hooks"); !nested {
				inline = newObject()
				inline.set("hooks", v)
			}
			rendered, err := encodeOrdered(inline)
			if err != nil {
				return []Finding{s.unreadable(manifestSource, err)}
			}
			findings = append(findings, s.scanJSONHooks(manifestSource, rendered)...)
		default:
			return []Finding{unreadableFinding(req, manifestSource, errors.New("plugin manifest hooks entry has an unexpected type"))}
		}
		break
	}
	seen := []string{}
	for _, path := range files {
		if containsPath(seen, path) {
			continue
		}
		seen = append(seen, path)
		findings = append(findings, s.scanFile(pluginSource(path))...)
		if s.exceeded != nil {
			break
		}
	}
	return findings
}

func containsPath(list []string, value string) bool {
	for _, existing := range list {
		if samePath(existing, value) {
			return true
		}
	}
	return false
}
