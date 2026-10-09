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

package config

import (
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"
)

// claudePluginRegistryMaxBytes bounds installed_plugins.json.
const claudePluginRegistryMaxBytes = 4 << 20

// claudePluginMCPPrefix starts the server segment of a plugin MCP tool name:
// Claude Code calls the server kit-time of plugin usm-kit
// mcp__plugin_usm-kit_kit-time__<tool>.
const claudePluginMCPPrefix = "plugin_"

// claudePluginMCPServers lists the MCP servers the Claude Code plugins
// installed under claudeDir bundle: the .mcp.json at a plugin's install
// path, or mcpServers in its .claude-plugin/plugin.json, inline or as a
// file. Each is named plugin:<plugin>:<server>, whose tool-name form
// (MCPToolServerName) is the one Claude Code's tool names carry, with
// ${CLAUDE_PLUGIN_ROOT} expanded. The hooks match asset_policy.mcp rules
// against them: a server shipped in a plugin sidestepped a denied command
// rule (GAP-1191).
func claudePluginMCPServers(claudeDir string) []MCPServerEntry {
	data, err := readMCPConfigFile(filepath.Join(claudeDir, "plugins", "installed_plugins.json"), claudePluginRegistryMaxBytes)
	if err != nil {
		return nil
	}
	var registry struct {
		Plugins map[string]json.RawMessage `json:"plugins"`
	}
	if json.Unmarshal(data, &registry) != nil {
		return nil
	}
	ids := make([]string, 0, len(registry.Plugins))
	for id := range registry.Plugins {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	type record struct {
		InstallPath string `json:"installPath"`
	}
	var out []MCPServerEntry
	for _, id := range ids {
		var records []record
		if json.Unmarshal(registry.Plugins[id], &records) != nil {
			var one record
			if json.Unmarshal(registry.Plugins[id], &one) != nil {
				continue
			}
			records = []record{one}
		}
		plugin, _, _ := strings.Cut(id, "@")
		if strings.TrimSpace(plugin) == "" {
			continue
		}
		for _, r := range records {
			root := strings.TrimSpace(r.InstallPath)
			if !filepath.IsAbs(root) {
				continue
			}
			for _, entry := range claudePluginRootMCPServers(filepath.Clean(root)) {
				entry.Name = "plugin:" + plugin + ":" + entry.Name
				out = append(out, entry)
			}
		}
	}
	return dedupMCPEntries(out)
}

// claudePluginRootMCPServers reads the MCP servers of the plugin at root.
func claudePluginRootMCPServers(root string) []MCPServerEntry {
	entries, _ := readMCPFromDotMCPJSON(filepath.Join(root, ".mcp.json"))
	if data, err := readMCPConfigFile(filepath.Join(root, ".claude-plugin", "plugin.json"), maxMCPConfigFileBytes); err == nil {
		var manifest map[string]any
		if json.Unmarshal(data, &manifest) == nil {
			switch servers := manifest["mcpServers"].(type) {
			case map[string]any:
				inline, _ := readMCPFromAnyPaths(manifest, []string{"mcpServers"})
				entries = append(entries, inline...)
			case string:
				if path := filepath.Join(root, filepath.FromSlash(servers)); !filepath.IsAbs(servers) &&
					strings.HasPrefix(filepath.Clean(path), root+string(filepath.Separator)) {
					file, _ := readMCPFromDotMCPJSON(path)
					entries = append(entries, file...)
				}
			}
		}
	}
	expand := func(value string) string { return strings.ReplaceAll(value, "${CLAUDE_PLUGIN_ROOT}", root) }
	for i := range entries {
		entries[i].Command, entries[i].URL, entries[i].CWD = expand(entries[i].Command), expand(entries[i].URL), expand(entries[i].CWD)
		for j := range entries[i].Args {
			entries[i].Args[j] = expand(entries[i].Args[j])
		}
	}
	return entries
}

// lookupClaudePluginMCPServer finds the plugin server a Claude Code tool call
// names (plugin_<plugin>_<server>, or the configured plugin:<plugin>:<server>).
func lookupClaudePluginMCPServer(claudeDir, name string) (MCPServerEntry, bool) {
	name = strings.TrimSpace(name)
	if !strings.HasPrefix(name, claudePluginMCPPrefix) && !strings.HasPrefix(name, "plugin:") {
		return MCPServerEntry{}, false
	}
	return lookupMCPToolServer("claudecode", claudePluginMCPServers(claudeDir), name)
}
