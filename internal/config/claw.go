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
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// openclawConfig represents the structure of openclaw.json.
type openclawConfig struct {
	Agents struct {
		Defaults struct {
			Workspace string `json:"workspace"`
		} `json:"defaults"`
	} `json:"agents"`
	Skills struct {
		Load struct {
			ExtraDirs []string `json:"extraDirs"`
		} `json:"load"`
	} `json:"skills"`
}

// MCPServerEntry represents a single MCP server from openclaw.json mcp.servers.
type MCPServerEntry struct {
	Name      string            `json:"name"`
	Command   string            `json:"command,omitempty"`
	Args      []string          `json:"args,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
	URL       string            `json:"url,omitempty"`
	Transport string            `json:"transport,omitempty"`
}

// expandPath expands ~ to home directory.
func expandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, path[2:])
		}
	}
	return path
}

// readOpenclawConfig reads and parses the openclaw.json config file.
func readOpenclawConfig(configFile string) (*openclawConfig, error) {
	path := expandPath(configFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var oc openclawConfig
	if err := json.Unmarshal(data, &oc); err != nil {
		return nil, err
	}
	return &oc, nil
}

// ReadMCPServers returns the MCP servers for the active connector.
// When guardrail.connector is set, it dispatches to the connector-specific
// reader. Falls back to the OpenClaw path for backward compatibility.
func (c *Config) ReadMCPServers() ([]MCPServerEntry, error) {
	connector := c.Guardrail.Connector
	if connector == "" {
		connector = string(c.Claw.Mode)
	}
	return c.ReadMCPServersForConnector(connector)
}

// ReadMCPServersForConnector returns MCP servers for a specific connector.
func (c *Config) ReadMCPServersForConnector(connector string) ([]MCPServerEntry, error) {
	switch connector {
	case "claudecode":
		return readMCPServersClaudeCode()
	case "codex":
		return readMCPServersCodex()
	case "zeptoclaw":
		return readMCPServersZeptoClaw()
	default:
		return readMCPServersOpenClaw(c.Claw.ConfigFile)
	}
}

func readMCPServersOpenClaw(configFile string) ([]MCPServerEntry, error) {
	entries, err := readMCPServersViaCLI()
	if err == nil {
		return entries, nil
	}
	return readMCPServersFromFile(configFile)
}

func readMCPServersViaCLI() ([]MCPServerEntry, error) {
	cmd := exec.Command("openclaw", "config", "get", "mcp.servers")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("config: openclaw config get mcp.servers: %w", err)
	}
	return parseMCPServersJSON(stdout.Bytes())
}

func readMCPServersFromFile(configFile string) ([]MCPServerEntry, error) {
	path := expandPath(configFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}

	mcpBlock, ok := raw["mcp"]
	if !ok {
		return nil, nil
	}

	var mcpObj map[string]json.RawMessage
	if err := json.Unmarshal(mcpBlock, &mcpObj); err != nil {
		return nil, fmt.Errorf("config: parse mcp block: %w", err)
	}

	serversBlock, ok := mcpObj["servers"]
	if !ok {
		return nil, nil
	}

	return parseMCPServersJSON(serversBlock)
}

func parseMCPServersJSON(data []byte) ([]MCPServerEntry, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, nil
	}

	var servers map[string]struct {
		Command   string            `json:"command"`
		Args      []string          `json:"args"`
		Env       map[string]string `json:"env"`
		URL       string            `json:"url"`
		Transport string            `json:"transport"`
	}
	if err := json.Unmarshal(trimmed, &servers); err != nil {
		return nil, fmt.Errorf("config: parse mcp servers: %w", err)
	}

	entries := make([]MCPServerEntry, 0, len(servers))
	for name, s := range servers {
		entries = append(entries, MCPServerEntry{
			Name:      name,
			Command:   s.Command,
			Args:      s.Args,
			Env:       s.Env,
			URL:       s.URL,
			Transport: s.Transport,
		})
	}
	return entries, nil
}

func workspaceSkillsDir(homeDir string, oc *openclawConfig) string {
	workspace := filepath.Join(homeDir, "workspace")
	if oc != nil && oc.Agents.Defaults.Workspace != "" {
		workspace = expandPath(oc.Agents.Defaults.Workspace)
	}
	return filepath.Join(workspace, "skills")
}

// SkillDirs returns the skill directories for the active claw mode.
// Order: workspace/skills → extraDirs from openclaw.json → home_dir/skills.
// OpenClaw defaults the workspace to ~/.openclaw/workspace even when the
// path is omitted from openclaw.json, so we always include that fallback.
func (c *Config) SkillDirs() []string {
	homeDir := expandPath(c.Claw.HomeDir)
	var dirs []string

	if oc, err := readOpenclawConfig(c.Claw.ConfigFile); err == nil {
		dirs = append(dirs, workspaceSkillsDir(homeDir, oc))
		for _, d := range oc.Skills.Load.ExtraDirs {
			dirs = append(dirs, expandPath(d))
		}
	} else {
		dirs = append(dirs, workspaceSkillsDir(homeDir, nil))
	}

	dirs = append(dirs, filepath.Join(homeDir, "skills"))

	return dedup(dirs)
}

// PluginDirs returns the plugin directories for the active claw mode.
// For OpenClaw, plugins (extensions) live under claw_home/extensions.
func (c *Config) PluginDirs() []string {
	homeDir := expandPath(c.Claw.HomeDir)
	return []string{filepath.Join(homeDir, "extensions")}
}

// InstalledSkillCandidates returns possible on-disk paths for a named skill,
// ordered by the claw mode's resolution priority.
func (c *Config) InstalledSkillCandidates(skillName string) []string {
	name := skillName
	if strings.Contains(name, "/") {
		parts := strings.SplitN(name, "/", 2)
		name = parts[len(parts)-1]
	}
	name = strings.TrimPrefix(name, "@")

	dirs := c.SkillDirs()
	candidates := make([]string, 0, len(dirs))
	for _, dir := range dirs {
		candidates = append(candidates, filepath.Join(dir, name))
	}
	return candidates
}

// ClawHomeDir returns the resolved home directory for the active claw framework.
func (c *Config) ClawHomeDir() string {
	return expandPath(c.Claw.HomeDir)
}

// dedup removes duplicate paths while preserving order.
func dedup(paths []string) []string {
	seen := make(map[string]bool, len(paths))
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// SkillDirsForMode returns skill directories for a given mode.
// Used when config is not yet available.
func SkillDirsForMode(mode ClawMode, homeDir string) []string {
	if homeDir == "" {
		homeDir = "~/.openclaw"
	}
	homeDir = expandPath(homeDir)

	configFile := filepath.Join(homeDir, "openclaw.json")
	var dirs []string

	if oc, err := readOpenclawConfig(configFile); err == nil {
		dirs = append(dirs, workspaceSkillsDir(homeDir, oc))
		for _, d := range oc.Skills.Load.ExtraDirs {
			dirs = append(dirs, expandPath(d))
		}
	} else {
		dirs = append(dirs, workspaceSkillsDir(homeDir, nil))
	}

	dirs = append(dirs, filepath.Join(homeDir, "skills"))
	return dedup(dirs)
}

// SkillDirsForConnector returns skill directories for a specific connector.
func (c *Config) SkillDirsForConnector(connector string) []string {
	home, _ := os.UserHomeDir()
	cwd, _ := os.Getwd()

	switch connector {
	case "claudecode":
		return dedup([]string{
			filepath.Join(home, ".claude", "skills"),
			filepath.Join(cwd, ".claude", "skills"),
		})
	case "codex":
		return dedup([]string{
			filepath.Join(home, ".codex", "skills"),
			filepath.Join(cwd, ".codex", "skills"),
		})
	case "zeptoclaw":
		return dedup([]string{
			filepath.Join(home, ".zeptoclaw", "skills"),
			filepath.Join(cwd, ".zeptoclaw", "skills"),
		})
	default:
		return c.SkillDirs()
	}
}

// PluginDirsForConnector returns plugin directories for a specific connector.
func (c *Config) PluginDirsForConnector(connector string) []string {
	home, _ := os.UserHomeDir()

	switch connector {
	case "claudecode":
		return []string{
			filepath.Join(home, ".claude", "plugins"),
		}
	case "codex":
		return []string{
			filepath.Join(home, ".codex", "plugins"),
		}
	case "zeptoclaw":
		return []string{
			filepath.Join(home, ".zeptoclaw", "plugins"),
		}
	default:
		return c.PluginDirs()
	}
}

// --- Connector-specific MCP readers ---

func readMCPServersClaudeCode() ([]MCPServerEntry, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	cwd, _ := os.Getwd()

	var entries []MCPServerEntry

	settingsPath := filepath.Join(home, ".claude", "settings.json")
	if e, err := readMCPFromClaudeSettings(settingsPath); err == nil {
		entries = append(entries, e...)
	}

	mcpJsonPath := filepath.Join(cwd, ".mcp.json")
	if e, err := readMCPFromDotMCPJSON(mcpJsonPath); err == nil {
		entries = append(entries, e...)
	}

	return dedupMCPEntries(entries), nil
}

func readMCPServersCodex() ([]MCPServerEntry, error) {
	cwd, _ := os.Getwd()

	mcpJsonPath := filepath.Join(cwd, ".mcp.json")
	return readMCPFromDotMCPJSON(mcpJsonPath)
}

func readMCPServersZeptoClaw() ([]MCPServerEntry, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	cwd, _ := os.Getwd()

	var entries []MCPServerEntry

	configPath := filepath.Join(home, ".zeptoclaw", "config.json")
	if e, err := readMCPFromZeptoConfig(configPath); err == nil {
		entries = append(entries, e...)
	}

	mcpJsonPath := filepath.Join(cwd, ".mcp.json")
	if e, err := readMCPFromDotMCPJSON(mcpJsonPath); err == nil {
		entries = append(entries, e...)
	}

	return dedupMCPEntries(entries), nil
}

func readMCPFromClaudeSettings(path string) ([]MCPServerEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var settings struct {
		MCPServers map[string]struct {
			Command string            `json:"command"`
			Args    []string          `json:"args"`
			Env     map[string]string `json:"env"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal(data, &settings); err != nil {
		return nil, err
	}

	entries := make([]MCPServerEntry, 0, len(settings.MCPServers))
	for name, s := range settings.MCPServers {
		entries = append(entries, MCPServerEntry{
			Name:    name,
			Command: s.Command,
			Args:    s.Args,
			Env:     s.Env,
		})
	}
	return entries, nil
}

func readMCPFromDotMCPJSON(path string) ([]MCPServerEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var dotMCP struct {
		MCPServers map[string]struct {
			Command   string            `json:"command"`
			Args      []string          `json:"args"`
			Env       map[string]string `json:"env"`
			URL       string            `json:"url"`
			Transport string            `json:"transport"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal(data, &dotMCP); err != nil {
		return nil, err
	}

	entries := make([]MCPServerEntry, 0, len(dotMCP.MCPServers))
	for name, s := range dotMCP.MCPServers {
		entries = append(entries, MCPServerEntry{
			Name:      name,
			Command:   s.Command,
			Args:      s.Args,
			Env:       s.Env,
			URL:       s.URL,
			Transport: s.Transport,
		})
	}
	return entries, nil
}

func readMCPFromZeptoConfig(path string) ([]MCPServerEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg struct {
		MCP struct {
			Servers map[string]struct {
				Command   string            `json:"command"`
				Args      []string          `json:"args"`
				Env       map[string]string `json:"env"`
				URL       string            `json:"url"`
				Transport string            `json:"transport"`
			} `json:"servers"`
		} `json:"mcp"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	entries := make([]MCPServerEntry, 0, len(cfg.MCP.Servers))
	for name, s := range cfg.MCP.Servers {
		entries = append(entries, MCPServerEntry{
			Name:      name,
			Command:   s.Command,
			Args:      s.Args,
			Env:       s.Env,
			URL:       s.URL,
			Transport: s.Transport,
		})
	}
	return entries, nil
}

func dedupMCPEntries(entries []MCPServerEntry) []MCPServerEntry {
	seen := make(map[string]bool, len(entries))
	out := make([]MCPServerEntry, 0, len(entries))
	for _, e := range entries {
		if !seen[e.Name] {
			seen[e.Name] = true
			out = append(out, e)
		}
	}
	return out
}
