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

	toml "github.com/pelletier/go-toml/v2"
	yaml "gopkg.in/yaml.v3"
)

// tomlUnmarshal is a thin alias kept private to this package — it
// lets us swap the TOML implementation later without touching every
// call site, and keeps the import surface minimal at the top of the
// file.
func tomlUnmarshal(data []byte, v any) error { return toml.Unmarshal(data, v) }

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

// activeConnector returns the resolved connector name for this config.
// Precedence: explicit guardrail.connector → claw.mode → "openclaw".
//
// This is the single decision point for "which agent framework is this
// sidecar running against?" — every polymorphic reader (SkillDirs,
// PluginDirs, ReadMCPServers) goes through it so a future connector
// is wired in by adding one switch arm, not by editing N call sites.
func (c *Config) activeConnector() string {
	if c == nil {
		return "openclaw"
	}
	if name := strings.TrimSpace(c.Guardrail.Connector); name != "" {
		return name
	}
	if mode := strings.TrimSpace(string(c.Claw.Mode)); mode != "" {
		return mode
	}
	return "openclaw"
}

// ReadMCPServers returns the MCP servers for the active connector.
// When guardrail.connector is set, it dispatches to the connector-specific
// reader. Falls back to the OpenClaw path for backward compatibility.
func (c *Config) ReadMCPServers() ([]MCPServerEntry, error) {
	return c.ReadMCPServersForConnector(c.activeConnector())
}

// ReadMCPServersForConnector returns MCP servers for a specific connector.
func (c *Config) ReadMCPServersForConnector(connector string) ([]MCPServerEntry, error) {
	switch strings.ToLower(strings.TrimSpace(connector)) {
	case "claudecode":
		return readMCPServersClaudeCode()
	case "codex":
		return readMCPServersCodex()
	case "zeptoclaw":
		return readMCPServersZeptoClaw()
	case "hermes":
		return readMCPServersHermes()
	case "cursor":
		return readMCPServersCursor()
	case "windsurf":
		return readMCPServersWindsurf()
	case "geminicli":
		return readMCPServersGeminiCLI()
	case "copilot":
		return readMCPServersCopilot()
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

func parseMCPServersJSONArray(data []byte) ([]MCPServerEntry, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, nil
	}

	var servers []struct {
		Name      string            `json:"name"`
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
	for _, s := range servers {
		if strings.TrimSpace(s.Name) == "" {
			continue
		}
		entries = append(entries, MCPServerEntry{
			Name:      s.Name,
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

// skillDirsOpenClaw returns the OpenClaw-specific skill directory list.
// Kept private so SkillDirsForConnector's "openclaw" / default branch
// can call it without re-entering the polymorphic SkillDirs() dispatcher.
func (c *Config) skillDirsOpenClaw() []string {
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

// pluginDirsOpenClaw returns the OpenClaw-specific plugin (extension) dirs.
// Private for the same reason as skillDirsOpenClaw — avoids recursion when
// PluginDirsForConnector falls into its default arm.
func (c *Config) pluginDirsOpenClaw() []string {
	homeDir := expandPath(c.Claw.HomeDir)
	return []string{filepath.Join(homeDir, "extensions")}
}

// SkillDirs returns the skill directories for the active connector.
//
// Dispatches via activeConnector() — when guardrail.connector is set
// (claudecode, codex, zeptoclaw), the connector-specific paths are
// returned. With no connector configured, falls back to the OpenClaw
// layout (workspace/skills → extraDirs from openclaw.json → home_dir/skills),
// preserving backward compatibility for pre-S1.x deployments.
func (c *Config) SkillDirs() []string {
	return c.SkillDirsForConnector(c.activeConnector())
}

// PluginDirs returns the plugin directories for the active connector.
//
// Dispatches via activeConnector() — when guardrail.connector is set,
// the connector-specific layout is returned (e.g. ~/.codex/plugins
// for Codex). With no connector configured, falls back to the OpenClaw
// extensions directory (claw_home/extensions).
func (c *Config) PluginDirs() []string {
	return c.PluginDirsForConnector(c.activeConnector())
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

// SkillDirsForOpenClaw returns the skill directories for an OpenClaw
// installation rooted at homeDir. Used when no Config is available
// (early init paths, tests, fixed-mode fallbacks).
//
// This was previously named SkillDirsForMode(mode, home) but the
// `mode` argument was never honored — every code path used the
// OpenClaw layout regardless of the value passed. The rename makes
// the OpenClaw-only contract explicit; callers that need polymorphic
// dispatch should use Config.SkillDirsForConnector instead, which
// reads cfg.activeConnector() and dispatches correctly.
func SkillDirsForOpenClaw(homeDir string) []string {
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

// SkillDirsForConnector returns skill directories for a specific connector,
// independent of the config's active connector.
//
// Used by callers that need to enumerate paths for a connector other than
// the running one (e.g. multi-connector audits, doctor). Unknown connector
// names — including "" and "openclaw" — fall through to the OpenClaw
// layout via skillDirsOpenClaw().
func (c *Config) SkillDirsForConnector(connector string) []string {
	home, _ := os.UserHomeDir()
	cwd, _ := os.Getwd()

	switch strings.ToLower(strings.TrimSpace(connector)) {
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
	case "hermes":
		return []string{filepath.Join(home, ".hermes", "skills")}
	case "cursor":
		return dedup([]string{
			filepath.Join(cwd, ".cursor", "skills"),
			filepath.Join(cwd, ".agents", "skills"),
			filepath.Join(home, ".cursor", "skills"),
			filepath.Join(home, ".agents", "skills"),
		})
	case "windsurf":
		return nil
	case "geminicli":
		return dedup([]string{
			filepath.Join(cwd, ".gemini", "skills"),
			filepath.Join(cwd, ".agents", "skills"),
		})
	case "copilot":
		return dedup([]string{
			filepath.Join(cwd, ".github", "skills"),
			filepath.Join(cwd, ".agents", "skills"),
			filepath.Join(home, ".copilot", "skills"),
		})
	default:
		return c.skillDirsOpenClaw()
	}
}

// PluginDirsForConnector returns plugin directories for a specific connector,
// independent of the config's active connector. Unknown / empty / "openclaw"
// fall through to the OpenClaw extensions layout.
func (c *Config) PluginDirsForConnector(connector string) []string {
	home, _ := os.UserHomeDir()
	cwd, _ := os.Getwd()

	switch strings.ToLower(strings.TrimSpace(connector)) {
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
	case "hermes":
		return dedup([]string{
			filepath.Join(home, ".hermes", "plugins"),
			filepath.Join(cwd, ".hermes", "plugins"),
		})
	case "geminicli":
		return dedup([]string{
			filepath.Join(cwd, ".gemini", "extensions"),
			filepath.Join(home, ".gemini", "extensions"),
		})
	case "cursor", "windsurf", "copilot":
		return nil
	default:
		return c.pluginDirsOpenClaw()
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
	// Codex registers MCP servers in two places — the global
	// `~/.codex/config.toml` `[mcp_servers]` table and the
	// project-local `./.mcp.json` (a Codex SDK / Claude Code
	// convention). Pre-S5.x we only read `./.mcp.json`, which
	// silently dropped every globally-registered server. We now
	// read both, with the project-local file taking precedence so
	// per-project overrides win — matching how Codex itself layers
	// them at runtime.
	home, _ := os.UserHomeDir()
	cwd, _ := os.Getwd()

	var entries []MCPServerEntry
	if home != "" {
		tomlPath := filepath.Join(home, ".codex", "config.toml")
		if e, err := readMCPFromCodexConfigTOML(tomlPath); err == nil {
			entries = append(entries, e...)
		}
	}
	mcpJsonPath := filepath.Join(cwd, ".mcp.json")
	if e, err := readMCPFromDotMCPJSON(mcpJsonPath); err == nil {
		entries = append(entries, e...)
	}
	return dedupMCPEntries(entries), nil
}

// readMCPFromCodexConfigTOML parses the [mcp_servers] table out of
// ~/.codex/config.toml. Codex's documented schema is:
//
//	[mcp_servers.<name>]
//	command = "..."
//	args = ["..."]
//	env = { KEY = "value" }
//
// Returns an empty slice (not an error) for missing files / malformed
// TOML / missing block so callers can soft-fall back to the
// project-local .mcp.json. Uses pelletier/go-toml/v2 which is already
// a project dependency — no new module is added.
func readMCPFromCodexConfigTOML(path string) ([]MCPServerEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		MCPServers map[string]struct {
			Command   string            `toml:"command"`
			Args      []string          `toml:"args"`
			Env       map[string]string `toml:"env"`
			URL       string            `toml:"url"`
			Transport string            `toml:"transport"`
		} `toml:"mcp_servers"`
	}
	if err := tomlUnmarshal(data, &doc); err != nil {
		return nil, err
	}
	out := make([]MCPServerEntry, 0, len(doc.MCPServers))
	for name, cfg := range doc.MCPServers {
		out = append(out, MCPServerEntry{
			Name:      name,
			Command:   cfg.Command,
			Args:      cfg.Args,
			Env:       cfg.Env,
			URL:       cfg.URL,
			Transport: cfg.Transport,
		})
	}
	return out, nil
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

func readMCPServersHermes() ([]MCPServerEntry, error) {
	home, _ := os.UserHomeDir()
	return readMCPFromYAMLPath(filepath.Join(home, ".hermes", "config.yaml"), []string{"mcp", "servers"}, []string{"mcpServers"})
}

func readMCPServersCursor() ([]MCPServerEntry, error) {
	home, _ := os.UserHomeDir()
	cwd, _ := os.Getwd()
	var entries []MCPServerEntry
	if e, err := readMCPFromDotMCPJSON(filepath.Join(cwd, ".cursor", "mcp.json")); err == nil {
		entries = append(entries, e...)
	}
	if e, err := readMCPFromDotMCPJSON(filepath.Join(home, ".cursor", "mcp.json")); err == nil {
		entries = append(entries, e...)
	}
	return dedupMCPEntries(entries), nil
}

func readMCPServersWindsurf() ([]MCPServerEntry, error) {
	home, _ := os.UserHomeDir()
	var entries []MCPServerEntry
	for _, path := range []string{
		filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"),
		filepath.Join(home, ".codeium", "windsurf", "mcp.json"),
	} {
		if e, err := readMCPFromDotMCPJSON(path); err == nil {
			entries = append(entries, e...)
		}
	}
	return dedupMCPEntries(entries), nil
}

func readMCPServersGeminiCLI() ([]MCPServerEntry, error) {
	home, _ := os.UserHomeDir()
	return readMCPFromJSONPath(filepath.Join(home, ".gemini", "settings.json"), []string{"mcpServers"})
}

func readMCPServersCopilot() ([]MCPServerEntry, error) {
	home, _ := os.UserHomeDir()
	cwd, _ := os.Getwd()
	var entries []MCPServerEntry
	for _, path := range []string{
		filepath.Join(home, ".copilot", "mcp-config.json"),
		filepath.Join(cwd, ".github", "mcp.json"),
		filepath.Join(cwd, ".mcp.json"),
	} {
		if e, err := readMCPFromDotMCPJSON(path); err == nil {
			entries = append(entries, e...)
		}
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

func readMCPFromJSONPath(path string, paths ...[]string) ([]MCPServerEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return readMCPFromAnyPaths(doc, paths...)
}

func readMCPFromYAMLPath(path string, paths ...[]string) ([]MCPServerEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return readMCPFromAnyPaths(doc, paths...)
}

func readMCPFromAnyPaths(doc any, paths ...[]string) ([]MCPServerEntry, error) {
	var entries []MCPServerEntry
	for _, path := range paths {
		cursor := doc
		for _, key := range path {
			obj, ok := cursor.(map[string]any)
			if !ok {
				cursor = nil
				break
			}
			cursor = obj[key]
			if cursor == nil {
				break
			}
		}
		if cursor == nil {
			continue
		}
		data, err := json.Marshal(cursor)
		if err != nil {
			continue
		}
		trimmed := bytes.TrimSpace(data)
		if len(trimmed) == 0 {
			continue
		}
		var parsed []MCPServerEntry
		switch trimmed[0] {
		case '{':
			parsed, err = parseMCPServersJSON(trimmed)
		case '[':
			parsed, err = parseMCPServersJSONArray(trimmed)
		default:
			continue
		}
		if err == nil {
			entries = append(entries, parsed...)
		}
	}
	return dedupMCPEntries(entries), nil
}

func readMCPFromDotMCPJSON(path string) ([]MCPServerEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	if _, ok := raw["mcpServers"]; ok {
		return readMCPFromAnyPaths(raw, []string{"mcpServers"})
	}
	return readMCPFromAnyPaths(map[string]any{"mcpServers": raw}, []string{"mcpServers"})
}

func readMCPFromZeptoConfig(path string) ([]MCPServerEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg struct {
		MCP struct {
			Servers json.RawMessage `json:"servers"`
		} `json:"mcp"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if len(cfg.MCP.Servers) == 0 {
		return nil, nil
	}

	trimmed := bytes.TrimSpace(cfg.MCP.Servers)
	if len(trimmed) == 0 {
		return nil, nil
	}
	switch trimmed[0] {
	case '{':
		return parseMCPServersJSON(cfg.MCP.Servers)
	case '[':
		return parseMCPServersJSONArray(cfg.MCP.Servers)
	default:
		return nil, nil
	}
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
