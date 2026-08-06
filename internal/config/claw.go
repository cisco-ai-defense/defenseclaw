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
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/claudecodepath"
	gatewayconnector "github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/hermespath"
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
	Name             string            `json:"name"`
	Command          string            `json:"command,omitempty"`
	Args             []string          `json:"args,omitempty"`
	Env              map[string]string `json:"env,omitempty"`
	CWD              string            `json:"cwd,omitempty"`
	URL              string            `json:"url,omitempty"`
	Transport        string            `json:"transport,omitempty"`
	Headers          map[string]string `json:"headers,omitempty"`
	AuthProviderType string            `json:"authProviderType,omitempty"`
	OAuth            map[string]any    `json:"oauth,omitempty"`
	Disabled         bool              `json:"disabled,omitempty"`
	DisabledTools    []string          `json:"disabledTools,omitempty"`
	Source           string            `json:"source,omitempty"`
	SourceScope      string            `json:"source_scope,omitempty"`
	TrustRequired    bool              `json:"trust_required,omitempty"`
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
		return normalizeConnectorKey(name)
	}
	if mode := strings.TrimSpace(string(c.Claw.Mode)); mode != "" {
		return normalizeConnectorKey(mode)
	}
	return "openclaw"
}

// activeConnectors returns the configured connector roster for this config, in
// deterministic (sorted) order. Unlike activeConnector(), this plural list is
// a roster surface: an unconfigured install returns an empty slice instead of
// fabricating the legacy "openclaw" floor. The singular activeConnector()
// keeps that default for path-resolution/back-compat callers that explicitly
// need it.
func (c *Config) activeConnectors() []string {
	if c == nil || !c.HasConnectorConfigured() {
		return nil
	}
	if len(c.Guardrail.Connectors) > 0 {
		names := make([]string, 0, len(c.Guardrail.Connectors))
		seen := make(map[string]struct{}, len(c.Guardrail.Connectors))
		for name := range c.Guardrail.Connectors {
			if normalized := normalizeConnectorKey(name); normalized != "" {
				if _, ok := seen[normalized]; ok {
					continue
				}
				seen[normalized] = struct{}{}
				names = append(names, normalized)
			}
		}
		if len(names) > 0 {
			sort.Strings(names)
			return names
		}
	}
	return []string{c.activeConnector()}
}

// HasConnectorConfigured reports whether this config explicitly selects at
// least one connector — i.e. the operator has actually run setup. It is the
// Go mirror of Python's Config.has_connector_configured() (mcp.md M1, the
// phantom-openclaw root) and lets callers distinguish a genuinely
// unconfigured install from an explicit openclaw one.
//
// activeConnectors() is wired to this helper so Go roster/status/runtime
// callers mirror Python list semantics on a zero-config install. The singular
// activeConnector() deliberately keeps flooring to "openclaw" for legacy path
// dispatchers; callers using that API to touch connector state must check this
// helper first when zero-config behavior matters.
func (c *Config) HasConnectorConfigured() bool {
	if c == nil {
		return false
	}
	if len(c.Guardrail.Connectors) > 0 {
		for name := range c.Guardrail.Connectors {
			if normalizeConnectorKey(name) != "" {
				return true
			}
		}
	}
	if strings.TrimSpace(c.Guardrail.Connector) != "" {
		return true
	}
	if strings.TrimSpace(string(c.Claw.Mode)) != "" {
		return true
	}
	return false
}

// ActiveConnector returns the resolved connector name for external packages
// that need to stamp connector-scoped telemetry/resource attributes.
func (c *Config) ActiveConnector() string {
	return c.activeConnector()
}

// ActiveConnectors returns the full resolved set of connector names
// (sorted) for external packages — notably the gateway boot loop and the
// TUI — that need to enumerate every active connector rather than just
// the primary one.
func (c *Config) ActiveConnectors() []string {
	return c.activeConnectors()
}

// ReadMCPServers returns the MCP servers for the active connector.
// When guardrail.connector is set, it dispatches to the connector-specific
// reader. Falls back to the OpenClaw path for backward compatibility.
func (c *Config) ReadMCPServers() ([]MCPServerEntry, error) {
	return c.ReadMCPServersForConnector(c.activeConnector())
}

// ReadMCPServersForConnector returns MCP servers for a specific connector.
func (c *Config) ReadMCPServersForConnector(connector string) ([]MCPServerEntry, error) {
	workspaceDir := ""
	if c != nil {
		workspaceDir = c.ConnectorWorkspaceDir()
	}
	switch normalizeConnectorKey(connector) {
	case "claudecode":
		return readMCPServersClaudeCode(workspaceDir)
	case "codex":
		return readMCPServersCodex(workspaceDir)
	case "zeptoclaw":
		return readMCPServersZeptoClaw(workspaceDir)
	case "hermes":
		return readMCPServersHermes()
	case "cursor":
		return readMCPServersCursor(workspaceDir)
	case "windsurf":
		return readMCPServersWindsurf()
	case "geminicli":
		return readMCPServersGeminiCLI()
	case "copilot":
		return readMCPServersCopilot(workspaceDir)
	case "openhands":
		return readMCPServersOpenHands()
	case "opencode":
		return readMCPServersOpenCode(workspaceDir)
	case "amp":
		return readMCPServersAMP(workspaceDir)
	case "antigravity":
		return readMCPServersAntigravity(workspaceDir)
	case "omnigent":
		return nil, nil
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
		Command          string            `json:"command"`
		Args             []string          `json:"args"`
		Env              map[string]string `json:"env"`
		CWD              string            `json:"cwd"`
		ServerURL        string            `json:"serverUrl"`
		URL              string            `json:"url"`
		Transport        string            `json:"transport"`
		Headers          map[string]string `json:"headers"`
		AuthProviderType string            `json:"authProviderType"`
		OAuth            map[string]any    `json:"oauth"`
		Disabled         bool              `json:"disabled"`
		DisabledTools    []string          `json:"disabledTools"`
	}
	if err := json.Unmarshal(trimmed, &servers); err != nil {
		return nil, fmt.Errorf("config: parse mcp servers: %w", err)
	}

	entries := make([]MCPServerEntry, 0, len(servers))
	for name, s := range servers {
		url := s.ServerURL
		if url == "" {
			url = s.URL
		}
		entries = append(entries, MCPServerEntry{
			Name:             name,
			Command:          s.Command,
			Args:             s.Args,
			Env:              s.Env,
			CWD:              s.CWD,
			URL:              url,
			Transport:        s.Transport,
			Headers:          s.Headers,
			AuthProviderType: s.AuthProviderType,
			OAuth:            s.OAuth,
			Disabled:         s.Disabled,
			DisabledTools:    s.DisabledTools,
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
		Name             string            `json:"name"`
		Command          string            `json:"command"`
		Args             []string          `json:"args"`
		Env              map[string]string `json:"env"`
		CWD              string            `json:"cwd"`
		ServerURL        string            `json:"serverUrl"`
		URL              string            `json:"url"`
		Transport        string            `json:"transport"`
		Headers          map[string]string `json:"headers"`
		AuthProviderType string            `json:"authProviderType"`
		OAuth            map[string]any    `json:"oauth"`
		Disabled         bool              `json:"disabled"`
		DisabledTools    []string          `json:"disabledTools"`
	}
	if err := json.Unmarshal(trimmed, &servers); err != nil {
		return nil, fmt.Errorf("config: parse mcp servers: %w", err)
	}

	entries := make([]MCPServerEntry, 0, len(servers))
	for _, s := range servers {
		if strings.TrimSpace(s.Name) == "" {
			continue
		}
		url := s.ServerURL
		if url == "" {
			url = s.URL
		}
		entries = append(entries, MCPServerEntry{
			Name:             s.Name,
			Command:          s.Command,
			Args:             s.Args,
			Env:              s.Env,
			CWD:              s.CWD,
			URL:              url,
			Transport:        s.Transport,
			Headers:          s.Headers,
			AuthProviderType: s.AuthProviderType,
			OAuth:            s.OAuth,
			Disabled:         s.Disabled,
			DisabledTools:    s.DisabledTools,
		})
	}
	return entries, nil
}

// ParseMCPServersJSON is the exported wrapper around parseMCPServersJSON
// so packages outside `config` (e.g. inventory's AI-discovery scanner)
// can enumerate the servers declared inside a matched `mcp.json` /
// `.cursor/mcp.json` / claude-desktop config file without duplicating the
// parser. The input is the raw file bytes; the output is one
// MCPServerEntry per top-level key in the JSON object form
// (`{"mcpServers": {...}}` callers must pass the inner `mcpServers`
// object; plain-object callers pass their whole file). Callers that need
// the array shape should use ParseMCPServersJSONArray.
func ParseMCPServersJSON(data []byte) ([]MCPServerEntry, error) {
	return parseMCPServersJSON(data)
}

// ParseMCPServersJSONArray is the exported wrapper around
// parseMCPServersJSONArray for callers that need the alternate top-level
// array form (`[{"name": "...", ...}, ...]`).
func ParseMCPServersJSONArray(data []byte) ([]MCPServerEntry, error) {
	return parseMCPServersJSONArray(data)
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
// the connector-specific layout is returned. With no connector configured,
// falls back to the OpenClaw
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
	return c.ConnectorHomeDir(c.activeConnector())
}

func connectorEnvHome(variable, defaultDir string) string {
	if configured := strings.TrimSpace(os.Getenv(variable)); configured != "" {
		configured = expandPath(configured)
		if !filepath.IsAbs(configured) {
			if absolute, err := filepath.Abs(configured); err == nil {
				configured = absolute
			}
		}
		return filepath.Clean(configured)
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, defaultDir)
}

// ConnectorWorkspaceDir returns the explicitly pinned project/workspace root
// for connectors whose hook or component surfaces are repository-scoped. Empty
// means "global/user scope"; the daemon must not infer a workspace from its
// own cwd because it usually starts from the DefenseClaw data directory.
func (c *Config) ConnectorWorkspaceDir() string {
	root := ""
	if c != nil {
		root = strings.TrimSpace(c.Claw.WorkspaceDir)
	}
	if root == "" {
		return ""
	}
	root = expandPath(root)
	if !filepath.IsAbs(root) {
		if abs, err := filepath.Abs(root); err == nil {
			root = abs
		}
	}
	return filepath.Clean(root)
}

// ConnectorHomeDir returns the conventional home/config root for a connector.
// OpenClaw uses the configured claw.home_dir; the hook-native connectors use
// the vendor paths their setup and discovery flows write/read.
func (c *Config) ConnectorHomeDir(connector string) string {
	home, _ := os.UserHomeDir()

	switch normalizeConnectorKey(connector) {
	case "claudecode":
		return connectorEnvHome("CLAUDE_CONFIG_DIR", ".claude")
	case "codex":
		return connectorEnvHome("CODEX_HOME", ".codex")
	case "zeptoclaw":
		return filepath.Join(home, ".zeptoclaw")
	case "hermes":
		return hermespath.HomeDir()
	case "cursor":
		return filepath.Join(home, ".cursor")
	case "windsurf":
		boundHome, err := windsurfUserHome()
		if err != nil {
			return ""
		}
		return filepath.Join(boundHome, ".codeium", "windsurf")
	case "geminicli":
		return filepath.Join(home, ".gemini")
	case "copilot":
		return filepath.Join(home, ".copilot")
	case "openhands":
		if workspace := c.ConnectorWorkspaceDir(); workspace != "" {
			return filepath.Join(workspace, ".openhands")
		}
		return filepath.Join(home, ".openhands")
	case "antigravity":
		// agy's marketing-facing install dir; matches
		// connector_paths.connector_home("antigravity") on the Python
		// side. Never fall through to OpenClaw's home_dir.
		return filepath.Join(home, ".gemini", "antigravity-cli")
	case "opencode":
		// opencode keeps its config under ~/.config/opencode/ (XDG-style);
		// matches connector_paths.connector_home("opencode").
		return filepath.Join(home, ".config", "opencode")
	case "amp":
		// Amp uses this same config home on macOS, Linux, and native
		// Windows (%USERPROFILE%\.config\amp).
		return filepath.Join(home, ".config", "amp")
	case "omnigent":
		if configHome := strings.TrimSpace(os.Getenv("OMNIGENT_CONFIG_HOME")); configHome != "" {
			return expandPath(configHome)
		}
		return filepath.Join(home, ".omnigent")
	default:
		if c == nil {
			return expandPath("~/.openclaw")
		}
		return expandPath(c.Claw.HomeDir)
	}
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

func dedupNonEmpty(paths []string) []string {
	seen := make(map[string]bool, len(paths))
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

func workspaceJoin(workspace string, parts ...string) string {
	workspace = strings.TrimSpace(workspace)
	if workspace == "" {
		return ""
	}
	all := append([]string{workspace}, parts...)
	return filepath.Join(all...)
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
	cwd := c.ConnectorWorkspaceDir()

	switch normalizeConnectorKey(connector) {
	case "claudecode":
		configDir := c.ConnectorHomeDir("claudecode")
		dirs := []string{
			filepath.Join(configDir, "skills"),
			filepath.Join(configDir, "commands"),
			workspaceJoin(cwd, ".claude", "commands"),
		}
		dirs = append(dirs, claudecodepath.ProjectSkillDirs(cwd)...)
		return dedupNonEmpty(dirs)
	case "codex":
		dirs := make([]string, 0, 4)
		for _, layer := range gatewayconnector.CodexProjectLayerDirs(cwd) {
			dirs = append(dirs, filepath.Join(layer, ".agents", "skills"))
		}
		dirs = append(dirs, gatewayconnector.CodexPersonalSkillsPath())
		if runtime.GOOS != "windows" {
			dirs = append(dirs, filepath.FromSlash("/etc/codex/skills"))
		}
		return dedupNonEmpty(dirs)
	case "zeptoclaw":
		return dedupNonEmpty([]string{
			filepath.Join(home, ".zeptoclaw", "skills"),
			workspaceJoin(cwd, ".zeptoclaw", "skills"),
		})
	case "hermes":
		return []string{filepath.Join(hermespath.HomeDir(), "skills")}
	case "cursor":
		return dedupNonEmpty([]string{
			filepath.Join(home, ".cursor", "skills"),
			filepath.Join(home, ".agents", "skills"),
			workspaceJoin(cwd, ".cursor", "skills"),
			workspaceJoin(cwd, ".agents", "skills"),
		})
	case "windsurf":
		boundHome, err := windsurfUserHome()
		if err != nil {
			return nil
		}
		return dedupNonEmpty([]string{
			filepath.Join(boundHome, ".codeium", "windsurf", "skills"),
			filepath.Join(boundHome, ".agents", "skills"),
			workspaceJoin(cwd, ".windsurf", "skills"),
			workspaceJoin(cwd, ".agents", "skills"),
		})
	case "opencode", "omnigent":
		// These connectors have no documented local skills surface. Keep
		// them isolated from OpenClaw's skill directories.
		return nil
	case "amp":
		return ampSkillDirs(home, cwd)
	case "antigravity":
		return dedupNonEmpty([]string{
			filepath.Join(home, ".gemini", "config", "skills"),
			workspaceJoin(cwd, ".agents", "skills"),
			workspaceJoin(cwd, ".agent", "skills"),
		})
	case "geminicli":
		return dedupNonEmpty([]string{
			filepath.Join(home, ".gemini", "skills"),
			workspaceJoin(cwd, ".gemini", "skills"),
			workspaceJoin(cwd, ".agents", "skills"),
		})
	case "copilot":
		return dedupNonEmpty([]string{
			filepath.Join(home, ".copilot", "skills"),
			workspaceJoin(cwd, ".github", "skills"),
			workspaceJoin(cwd, ".agents", "skills"),
		})
	case "openhands":
		return dedupNonEmpty([]string{
			workspaceJoin(cwd, ".agents", "skills"),
			workspaceJoin(cwd, ".openhands", "skills"),
			workspaceJoin(cwd, ".openhands", "microagents"),
			filepath.Join(home, ".agents", "skills"),
			filepath.Join(home, ".openhands", "skills"),
			filepath.Join(home, ".openhands", "microagents"),
			filepath.Join(home, ".openhands", "skills", "installed"),
			filepath.Join(home, ".openhands", "cache", "skills", "public-skills", "skills"),
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
	cwd := c.ConnectorWorkspaceDir()

	switch normalizeConnectorKey(connector) {
	case "claudecode":
		configDir := c.ConnectorHomeDir("claudecode")
		pluginParent := strings.TrimSpace(os.Getenv("CLAUDE_CODE_PLUGIN_CACHE_DIR"))
		if pluginParent == "" {
			pluginParent = filepath.Join(configDir, "plugins")
		} else {
			pluginParent = expandPath(pluginParent)
		}
		dirs := []string{
			filepath.Join(pluginParent, "cache"),
			filepath.Join(configDir, "skills"),
		}
		dirs = append(dirs, claudecodepath.ProjectSkillDirs(cwd)...)
		return dedupNonEmpty(dirs)
	case "codex":
		base := filepath.Join(c.ConnectorHomeDir("codex"), "plugins")
		return dedupNonEmpty(append(
			gatewayconnector.CodexPluginSourceDirs(cwd),
			filepath.Join(base, "cache"),
		))
	case "zeptoclaw":
		return []string{
			filepath.Join(home, ".zeptoclaw", "plugins"),
		}
	case "hermes":
		return dedupNonEmpty([]string{
			filepath.Join(hermespath.HomeDir(), "plugins"),
			workspaceJoin(cwd, ".hermes", "plugins"),
		})
	case "geminicli":
		return dedupNonEmpty([]string{
			filepath.Join(home, ".gemini", "extensions"),
			workspaceJoin(cwd, ".gemini", "extensions"),
		})
	case "antigravity":
		return dedupNonEmpty([]string{
			filepath.Join(home, ".gemini", "config", "plugins"),
			filepath.Join(home, ".gemini", "antigravity-cli", "plugins"),
			workspaceJoin(cwd, ".agents", "plugins"),
			workspaceJoin(cwd, "_agents", "plugins"),
		})
	case "amp":
		return dedupNonEmpty([]string{
			filepath.Join(home, ".config", "amp", "plugins"),
			workspaceJoin(cwd, ".amp", "plugins"),
		})
	case "cursor", "windsurf", "copilot", "openhands", "opencode", "omnigent":
		return nil
	default:
		return c.pluginDirsOpenClaw()
	}
}

// --- Connector-specific MCP readers ---

func readMCPServersClaudeCode(workspaceDir string) ([]MCPServerEntry, error) {
	cwd := strings.TrimSpace(workspaceDir)

	var entries []MCPServerEntry

	statePath := claudeCodeMCPStatePath()
	if local, user, err := readMCPFromClaudeState(statePath, cwd); err == nil {
		// Claude's documented precedence is local, project, then user.
		// dedupMCPEntries is first-wins, so preserve that order exactly.
		entries = append(entries, local...)
		if cwd != "" {
			mcpJSONPath := filepath.Join(cwd, ".mcp.json")
			if project, projectErr := readMCPFromDotMCPJSON(mcpJSONPath); projectErr == nil {
				entries = append(entries, project...)
			}
		}
		entries = append(entries, user...)
		return dedupMCPEntries(entries), nil
	}

	// A missing or malformed state file must not suppress a valid project
	// registry. Preserve the explicit-workspace-only rule.
	if cwd != "" {
		mcpJSONPath := filepath.Join(cwd, ".mcp.json")
		if e, err := readMCPFromDotMCPJSON(mcpJSONPath); err == nil {
			entries = append(entries, e...)
		}
	}

	return dedupMCPEntries(entries), nil
}

func claudeCodeMCPStatePath() string {
	if strings.TrimSpace(os.Getenv("CLAUDE_CONFIG_DIR")) != "" {
		return filepath.Join(connectorEnvHome("CLAUDE_CONFIG_DIR", ".claude"), ".claude.json")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".claude.json")
}

func readMCPFromClaudeState(path, workspaceDir string) (local, user []MCPServerEntry, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var state map[string]any
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, nil, err
	}

	if workspace := strings.TrimSpace(workspaceDir); workspace != "" {
		if projects, ok := state["projects"].(map[string]any); ok {
			for projectKey, projectValue := range projects {
				if !sameClaudeWorkspace(projectKey, workspace) {
					continue
				}
				if projectState, ok := projectValue.(map[string]any); ok {
					local, _ = readMCPFromAnyPaths(projectState, []string{"mcpServers"})
				}
				break
			}
		}
	}
	user, _ = readMCPFromAnyPaths(state, []string{"mcpServers"})
	return local, user, nil
}

func sameClaudeWorkspace(left, right string) bool {
	normalize := func(value string) string {
		value = expandPath(strings.TrimSpace(value))
		if absolute, err := filepath.Abs(value); err == nil {
			value = absolute
		}
		return filepath.Clean(value)
	}
	left = normalize(left)
	right = normalize(right)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
}

func readMCPServersCodex(workspaceDir string) ([]MCPServerEntry, error) {
	// Codex stores user and project MCP registries in config.toml
	// [mcp_servers] tables. Candidate project layers are read closest-first so
	// their entries take precedence, then the user layer fills remaining names.
	// Filesystem presence is discovery only: project entries carry
	// TrustRequired because Codex activates them only for trusted projects.
	cwd := strings.TrimSpace(workspaceDir)

	var entries []MCPServerEntry
	for _, layer := range gatewayconnector.CodexProjectLayerDirs(cwd) {
		projectPath := filepath.Join(layer, ".codex", "config.toml")
		if e, err := readMCPFromCodexConfigTOML(projectPath); err == nil {
			entries = append(entries, annotateCodexMCPEntries(e, projectPath, "project", true)...)
		}
	}
	userPath := filepath.Join(connectorEnvHome("CODEX_HOME", ".codex"), "config.toml")
	if e, err := readMCPFromCodexConfigTOML(userPath); err == nil {
		e = annotateCodexMCPEntries(e, userPath, "user", false)
		entries = append(entries, e...)
	}
	return dedupMCPEntries(entries), nil
}

func annotateCodexMCPEntries(entries []MCPServerEntry, source, scope string, trustRequired bool) []MCPServerEntry {
	for index := range entries {
		entries[index].Source = source
		entries[index].SourceScope = scope
		entries[index].TrustRequired = trustRequired
	}
	return entries
}

const maxCodexInventoryConfigBytes = 1 << 20

// readMCPFromCodexConfigTOML parses the [mcp_servers] table out of
// ~/.codex/config.toml. Codex's documented schema is:
//
//	[mcp_servers.<name>]
//	command = "..."
//	args = ["..."]
//	env = { KEY = "value" }
//
// The read is bounded and rejects reparse/symlink or changing inputs. Callers
// treat errors as an unsafe/unavailable layer and continue to lower-precedence
// project or user config.
func readMCPFromCodexConfigTOML(path string) ([]MCPServerEntry, error) {
	data, ok := gatewayconnector.ReadStableInventoryFile(path, maxCodexInventoryConfigBytes)
	if !ok {
		return nil, fmt.Errorf("Codex MCP config is unavailable, unstable, unsafe, or exceeds %d bytes: %s", maxCodexInventoryConfigBytes, path)
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

func readMCPServersZeptoClaw(workspaceDir string) ([]MCPServerEntry, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	cwd := strings.TrimSpace(workspaceDir)

	var entries []MCPServerEntry

	configPath := filepath.Join(home, ".zeptoclaw", "config.json")
	if e, err := readMCPFromZeptoConfig(configPath); err == nil {
		entries = append(entries, e...)
	}

	if cwd != "" {
		mcpJsonPath := filepath.Join(cwd, ".mcp.json")
		if e, err := readMCPFromDotMCPJSON(mcpJsonPath); err == nil {
			entries = append(entries, e...)
		}
	}

	return dedupMCPEntries(entries), nil
}

func readMCPServersHermes() ([]MCPServerEntry, error) {
	return readMCPFromYAMLPath(hermespath.ConfigPath(), []string{"mcp", "servers"}, []string{"mcpServers"})
}

func readMCPServersCursor(workspaceDir string) ([]MCPServerEntry, error) {
	home, _ := os.UserHomeDir()
	cwd := strings.TrimSpace(workspaceDir)
	var entries []MCPServerEntry
	if e, err := readMCPFromDotMCPJSON(filepath.Join(home, ".cursor", "mcp.json")); err == nil {
		entries = append(entries, e...)
	}
	if cwd != "" {
		if e, err := readMCPFromDotMCPJSON(filepath.Join(cwd, ".cursor", "mcp.json")); err == nil {
			entries = append(entries, e...)
		}
	}
	return dedupMCPEntries(entries), nil
}

func readMCPServersWindsurf() ([]MCPServerEntry, error) {
	home, err := windsurfUserHome()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(home, ".codeium", "windsurf", "mcp_config.json")
	entries, err := readMCPFromDotMCPJSON(path)
	if err != nil {
		return nil, nil
	}
	return dedupMCPEntries(entries), nil
}

func windsurfUserHome() (string, error) {
	configured := os.Getenv("WINDSURF_USER_HOME")
	if configured == "" {
		return os.UserHomeDir()
	}
	if strings.TrimSpace(configured) != configured ||
		strings.ContainsAny(configured, "\x00\r\n") ||
		!filepath.IsAbs(configured) ||
		filepath.Clean(configured) != configured {
		return "", fmt.Errorf("WINDSURF_USER_HOME is not an absolute normalized path")
	}
	return configured, nil
}

func readMCPServersGeminiCLI() ([]MCPServerEntry, error) {
	home, _ := os.UserHomeDir()
	return readMCPFromJSONPath(filepath.Join(home, ".gemini", "settings.json"), []string{"mcpServers"})
}

func readMCPServersCopilot(workspaceDir string) ([]MCPServerEntry, error) {
	home, _ := os.UserHomeDir()
	cwd := strings.TrimSpace(workspaceDir)
	var entries []MCPServerEntry
	paths := []string{filepath.Join(home, ".copilot", "mcp-config.json")}
	if cwd != "" {
		paths = append(paths, filepath.Join(cwd, ".github", "mcp.json"), filepath.Join(cwd, ".mcp.json"))
	}
	for _, path := range paths {
		if e, err := readMCPFromDotMCPJSON(path); err == nil {
			entries = append(entries, e...)
		}
	}
	return dedupMCPEntries(entries), nil
}

func readMCPServersOpenHands() ([]MCPServerEntry, error) {
	home, _ := os.UserHomeDir()
	return readMCPFromDotMCPJSON(filepath.Join(home, ".openhands", "mcp.json"))
}

// readMCPServersAntigravity reads Antigravity-native MCP config. agy
// documents global MCP at ~/.gemini/config/mcp_config.json and
// workspace MCP at <workspace>/.agents/mcp_config.json. The workspace
// file is consulted only when DefenseClaw has an explicitly pinned
// connector workspace; the daemon cwd is never inferred. Missing or
// malformed Antigravity files are soft failures and never fall back to
// OpenClaw's openclaw.json.
func readMCPServersAntigravity(workspaceDir string) ([]MCPServerEntry, error) {
	home, _ := os.UserHomeDir()
	cwd := strings.TrimSpace(workspaceDir)

	var entries []MCPServerEntry
	if home != "" {
		if e, err := readMCPFromJSONPath(filepath.Join(home, ".gemini", "config", "mcp_config.json"), []string{"mcpServers"}); err == nil {
			entries = append(entries, e...)
		}
	}
	if cwd != "" {
		if e, err := readMCPFromJSONPath(filepath.Join(cwd, ".agents", "mcp_config.json"), []string{"mcpServers"}); err == nil {
			entries = append(entries, e...)
		}
	}
	return dedupMCPEntries(entries), nil
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

const ampSettingsReadLimit int64 = 2 << 20

func ampClaudePluginCacheSkillDirs(home string) []string {
	const (
		maxDepth   = 4
		maxEntries = 4096
	)
	root := filepath.Join(home, ".claude", "plugins", "cache")
	info, err := os.Lstat(root)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil
	}
	type pendingDir struct {
		path  string
		depth int
	}
	pending := []pendingDir{{path: root}}
	inspected := 0
	var skillDirs []string
	for len(pending) > 0 && inspected < maxEntries {
		current := pending[0]
		pending = pending[1:]
		entries, err := readBoundedAMPDirectory(current.path, maxEntries-inspected)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			inspected++
			if entry.Type()&os.ModeSymlink != 0 || !entry.IsDir() {
				continue
			}
			childDepth := current.depth + 1
			child := filepath.Join(current.path, entry.Name())
			if strings.EqualFold(entry.Name(), "skills") {
				skillDirs = append(skillDirs, child)
				continue
			}
			if childDepth < maxDepth {
				pending = append(pending, pendingDir{path: child, depth: childDepth})
			}
		}
	}
	return dedupNonEmpty(skillDirs)
}

func ampManagedSettingsPath() string {
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(string(filepath.Separator), "Library", "Application Support", "ampcode", "managed-settings.json")
	case "linux":
		return filepath.Join(string(filepath.Separator), "etc", "ampcode", "managed-settings.json")
	case "windows":
		if programData := strings.TrimSpace(os.Getenv("ProgramData")); programData != "" {
			return filepath.Join(programData, "ampcode", "managed-settings.json")
		}
	}
	return ""
}

func ampSettingsPaths(home, workspace string, workspaceFirst bool) []string {
	user := []string{preferredAMPSettingsPath(
		filepath.Join(home, ".config", "amp", "settings.json"),
		filepath.Join(home, ".config", "amp", "settings.jsonc"),
	)}
	project := []string{preferredAMPSettingsPath(
		workspaceJoin(workspace, ".amp", "settings.json"),
		workspaceJoin(workspace, ".amp", "settings.jsonc"),
	)}
	managed := []string{ampManagedSettingsPath()}
	if workspaceFirst {
		return dedupNonEmpty(append(managed, append(project, user...)...))
	}
	return dedupNonEmpty(append(append(user, project...), managed...))
}

func ampSkillDirs(home, workspace string) []string {
	disableClaude := false
	var extraPath string
	// Read user then workspace so the documented workspace override wins.
	for _, path := range ampSettingsPaths(home, workspace, false) {
		doc, err := readJSONObjectJSONC(path)
		if err != nil {
			continue
		}
		if value, ok := doc["amp.skills.disableClaudeCodeSkills"].(bool); ok {
			disableClaude = value
		}
		if value, ok := doc["amp.skills.path"].(string); ok {
			extraPath = value
		}
	}

	dirs := []string{
		filepath.Join(home, ".config", "agents", "skills"),
		filepath.Join(home, ".agents", "skills"),
		filepath.Join(home, ".config", "amp", "skills"),
		workspaceJoin(workspace, ".agents", "skills"),
	}
	if !disableClaude {
		dirs = append(dirs,
			workspaceJoin(workspace, ".claude", "skills"),
			filepath.Join(home, ".claude", "skills"),
		)
		dirs = append(dirs, ampClaudePluginCacheSkillDirs(home)...)
	}
	for _, configured := range filepath.SplitList(extraPath) {
		configured = expandPath(strings.TrimSpace(configured))
		if configured == "" {
			continue
		}
		// Never resolve a relative path against the DefenseClaw daemon's cwd.
		// With a pinned workspace, relative additions are workspace-relative;
		// otherwise only the documented absolute/~ forms are actionable.
		if !filepath.IsAbs(configured) {
			if workspace == "" {
				continue
			}
			configured = filepath.Join(workspace, configured)
		}
		dirs = append(dirs, filepath.Clean(configured))
	}
	// Plugin-bundled skills are the lowest local precedence documented by
	// Amp. Only directory plugins can bundle a skills/ component; standalone
	// .ts plugins remain visible through plugin inventory, not this list.
	for _, pluginRoot := range dedupNonEmpty([]string{
		filepath.Join(home, ".config", "amp", "plugins"),
		workspaceJoin(workspace, ".amp", "plugins"),
	}) {
		entries, err := readBoundedAMPDirectory(pluginRoot, 4096)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				dirs = append(dirs, filepath.Join(pluginRoot, entry.Name(), "skills"))
			}
		}
	}
	return dedupNonEmpty(dirs)
}

func preferredAMPSettingsPath(primary, fallback string) string {
	for _, candidate := range []string{primary, fallback} {
		if candidate == "" {
			continue
		}
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return primary
}

func readBoundedAMPDirectory(path string, remaining int) ([]os.DirEntry, error) {
	if remaining <= 0 {
		return nil, nil
	}
	directory, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	entries, readErr := directory.ReadDir(remaining)
	closeErr := directory.Close()
	if readErr != nil && readErr != io.EOF {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	sort.Slice(entries, func(left, right int) bool {
		return strings.ToLower(entries[left].Name()) < strings.ToLower(entries[right].Name())
	})
	return entries, nil
}

func readJSONObjectJSONC(path string) (map[string]any, error) {
	data, err := readStableAMPSettingsFile(path)
	if err != nil {
		return nil, err
	}
	data = stripJSONCComments(data)
	data = stripJSONCTrailingCommas(data)
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return doc, nil
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

func readMCPFromOpenCodeConfig(path string) ([]MCPServerEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		MCP map[string]struct {
			Type        string            `json:"type"`
			Command     []string          `json:"command"`
			Environment map[string]string `json:"environment"`
			URL         string            `json:"url"`
		} `json:"mcp"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	entries := make([]MCPServerEntry, 0, len(doc.MCP))
	for name, cfg := range doc.MCP {
		kind := strings.ToLower(strings.TrimSpace(cfg.Type))
		if kind == "remote" || (kind == "" && cfg.URL != "" && len(cfg.Command) == 0) {
			entries = append(entries, MCPServerEntry{
				Name:      name,
				URL:       cfg.URL,
				Transport: "remote",
			})
			continue
		}
		command := ""
		var args []string
		if len(cfg.Command) > 0 {
			command = cfg.Command[0]
			if len(cfg.Command) > 1 {
				args = cfg.Command[1:]
			}
		}
		entries = append(entries, MCPServerEntry{
			Name:      name,
			Command:   command,
			Args:      args,
			Env:       cfg.Environment,
			Transport: "local",
		})
	}
	return entries, nil
}

func readMCPServersAMP(workspaceDir string) ([]MCPServerEntry, error) {
	home, _ := os.UserHomeDir()
	cwd := strings.TrimSpace(workspaceDir)
	var entries []MCPServerEntry

	for _, path := range ampSettingsPaths(home, cwd, true) {
		doc, err := readJSONObjectJSONC(path)
		if err != nil {
			continue
		}
		if found, err := readMCPFromAnyPaths(doc, []string{"amp.mcpServers"}); err == nil {
			entries = append(entries, found...)
		}
	}

	for _, skillRoot := range ampSkillDirs(home, cwd) {
		children, err := os.ReadDir(skillRoot)
		if err != nil {
			continue
		}
		for _, child := range children {
			if !child.IsDir() {
				continue
			}
			if found, err := readMCPFromDotMCPJSON(filepath.Join(skillRoot, child.Name(), "mcp.json")); err == nil {
				entries = append(entries, found...)
			}
		}
	}
	return dedupMCPEntries(entries), nil
}

func readStableAMPSettingsFile(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, fmt.Errorf("Amp settings source is not a regular file")
	}
	if before.Size() > ampSettingsReadLimit {
		return nil, fmt.Errorf("Amp settings source exceeds %d bytes", ampSettingsReadLimit)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	opened, statErr := file.Stat()
	data, readErr := io.ReadAll(io.LimitReader(file, ampSettingsReadLimit+1))
	closeErr := file.Close()
	if statErr != nil {
		return nil, statErr
	}
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, fmt.Errorf("Amp settings source changed during inspection")
	}
	if int64(len(data)) > ampSettingsReadLimit {
		return nil, fmt.Errorf("Amp settings source exceeds %d bytes", ampSettingsReadLimit)
	}
	after, err := os.Lstat(path)
	if err != nil || after.Mode()&os.ModeSymlink != 0 || !after.Mode().IsRegular() ||
		!os.SameFile(opened, after) || before.Size() != after.Size() ||
		!before.ModTime().Equal(after.ModTime()) {
		return nil, fmt.Errorf("Amp settings source changed during inspection")
	}
	return data, nil
}

func stripJSONCComments(data []byte) []byte {
	out := make([]byte, 0, len(data))
	inString := false
	escaped := false
	for i := 0; i < len(data); {
		b := data[i]
		if inString {
			out = append(out, b)
			if escaped {
				escaped = false
			} else if b == '\\' {
				escaped = true
			} else if b == '"' {
				inString = false
			}
			i++
			continue
		}
		if b == '"' {
			inString = true
			out = append(out, b)
			i++
			continue
		}
		if b == '/' && i+1 < len(data) && data[i+1] == '/' {
			i += 2
			for i < len(data) && data[i] != '\n' && data[i] != '\r' {
				i++
			}
			continue
		}
		if b == '/' && i+1 < len(data) && data[i+1] == '*' {
			i += 2
			for i+1 < len(data) && !(data[i] == '*' && data[i+1] == '/') {
				i++
			}
			if i+1 < len(data) {
				i += 2
			}
			continue
		}
		out = append(out, b)
		i++
	}
	return out
}

func stripJSONCTrailingCommas(data []byte) []byte {
	out := make([]byte, 0, len(data))
	inString := false
	escaped := false
	for i := 0; i < len(data); i++ {
		b := data[i]
		if inString {
			out = append(out, b)
			if escaped {
				escaped = false
			} else if b == '\\' {
				escaped = true
			} else if b == '"' {
				inString = false
			}
			continue
		}
		if b == '"' {
			inString = true
			out = append(out, b)
			continue
		}
		if b == ',' {
			j := i + 1
			for j < len(data) && (data[j] == ' ' || data[j] == '\t' || data[j] == '\n' || data[j] == '\r') {
				j++
			}
			if j < len(data) && (data[j] == '}' || data[j] == ']') {
				continue
			}
		}
		out = append(out, b)
	}
	return out
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
