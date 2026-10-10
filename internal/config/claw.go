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
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/claudecodepath"
	"github.com/defenseclaw/defenseclaw/internal/envvars"
	gatewayconnector "github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/hermespath"
	"github.com/defenseclaw/defenseclaw/internal/jsonc"
	"github.com/defenseclaw/defenseclaw/internal/legacyconnector"
	toml "github.com/pelletier/go-toml/v2"
	yaml "gopkg.in/yaml.v3"
)

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
	Bundled          bool              `json:"bundled,omitempty"`
	// Connector is the connector whose registry listed the server when a
	// managed gateway reads several users' registries (never serialized).
	Connector string `json:"-"`
	// Home is the user home a managed gateway read the server from (never
	// serialized). Two users, or two connectors of one user, may each list a
	// server under the same name.
	Home string `json:"-"`
	// Project is the project folder whose local or .mcp.json scope lists
	// the server (never serialized); empty for a user-scope server.
	Project string `json:"-"`
	// WorkDir is the folder the server starts in, as the managed Windows
	// enumerator checked it where the user profile is readable (GAP-1317):
	// absolute, inside Project or the user home, no link or reparse point
	// on the way, re-resolved after the check. WorkDirRefused is the folder
	// it did not accept and why ("<folder>: <reason>"). Only the
	// enumerator spool record sets them (never serialized), so no
	// configuration file a user writes can name a vetted folder.
	WorkDir        string `json:"-"`
	WorkDirRefused string `json:"-"`

	// codexBuiltinShape records an exact parser-level match before the caller
	// proves that the table came from a user-scope Codex config. It is never
	// serialized and must not be treated as provenance on its own.
	codexBuiltinShape bool
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
	return c.readMCPServersForConnectorIn(connector, workspaceDir)
}

// LookupMCPServerForConnector returns the connector's configured MCP server
// called name, read from the agent's working directory (when given) or the
// configured workspace. Runtime hooks carry only the server name; this gives
// the gateway the server's URL, command and transport so URL-pinned registry
// rules match at runtime the same way they do at admission (GAP-2488).
func (c *Config) LookupMCPServerForConnector(connector, workspaceDir, name string) (MCPServerEntry, bool) {
	name = strings.TrimSpace(name)
	if name == "" {
		return MCPServerEntry{}, false
	}
	workspaceDir = strings.TrimSpace(workspaceDir)
	if workspaceDir == "" && c != nil {
		workspaceDir = c.ConnectorWorkspaceDir()
	}
	entries, err := c.readMCPServersForConnectorIn(connector, workspaceDir)
	if err != nil {
		return MCPServerEntry{}, false
	}
	for _, e := range entries {
		if e.Name == name {
			return e, true
		}
	}
	return MCPServerEntry{}, false
}

// LookupMCPServerUnderHome is LookupMCPServerForConnector for a user whose
// home is not this process's: a standalone gateway runs as a service
// account and answers the hooks of every user, so the server a hook names
// is the one that user's agent configures (GAP-0576). Claude Code and
// Codex are read; for other connectors ok is false.
func LookupMCPServerUnderHome(connector, home, workspaceDir, name string) (MCPServerEntry, bool) {
	name, home = strings.TrimSpace(name), strings.TrimSpace(home)
	if name == "" || !filepath.IsAbs(home) {
		return MCPServerEntry{}, false
	}
	var entries []MCPServerEntry
	switch normalizeConnectorKey(connector) {
	case "claudecode":
		entries = readMCPServersClaudeCodeAt(filepath.Join(home, ".claude.json"),
			filepath.Join(home, ".claude", "settings.json"), workspaceDir)
		if entry, ok := lookupMCPToolServer(connector, entries, name); ok {
			return entry, true
		}
		return lookupClaudePluginMCPServer(filepath.Join(home, ".claude"), name)
	case "codex":
		entries = readMCPServersCodexAt(filepath.Join(home, ".codex", "config.toml"), workspaceDir)
	default:
		return MCPServerEntry{}, false
	}
	return lookupMCPToolServer(connector, entries, name)
}

// LookupMCPToolServerForConnector is LookupMCPServerForConnector for the
// server name a tool call carries, which an agent may have rewritten from
// the configured name (MCPToolServerName). The standalone hooks and gateway
// use it; Secure Client keeps the exact lookup of main (issue #1092).
func (c *Config) LookupMCPToolServerForConnector(connector, workspaceDir, name string) (MCPServerEntry, bool) {
	name = strings.TrimSpace(name)
	if name == "" {
		return MCPServerEntry{}, false
	}
	workspaceDir = strings.TrimSpace(workspaceDir)
	if workspaceDir == "" && c != nil {
		workspaceDir = c.ConnectorWorkspaceDir()
	}
	entries, err := c.readMCPServersForConnectorIn(connector, workspaceDir)
	if err != nil {
		return MCPServerEntry{}, false
	}
	if entry, ok := lookupMCPToolServer(connector, entries, name); ok {
		return entry, true
	}
	if normalizeConnectorKey(connector) == "claudecode" && (c == nil || !c.SecureClientIntegration()) {
		// A server a plugin bundles (GAP-1191).
		return lookupClaudePluginMCPServer(connectorEnvHome("CLAUDE_CONFIG_DIR", ".claude"), name)
	}
	return MCPServerEntry{}, false
}

// CodexMCPToolServerAmbiguous reports whether the caller's effective Codex
// configuration has distinct server names that produce the same hook tool
// segment. A hook without an explicit server name cannot distinguish them.
func (c *Config) CodexMCPToolServerAmbiguous(workspaceDir, toolServer string) bool {
	workspaceDir = strings.TrimSpace(workspaceDir)
	if workspaceDir == "" && c != nil {
		workspaceDir = c.ConnectorWorkspaceDir()
	}
	entries, err := c.readMCPServersForConnectorIn("codex", workspaceDir)
	return err == nil && codexMCPToolServerAmbiguous(entries, toolServer)
}

// CodexMCPToolServerAmbiguousUnderHome uses the managed caller's Codex
// configuration instead of the gateway service account's configuration.
func CodexMCPToolServerAmbiguousUnderHome(home, workspaceDir, toolServer string) bool {
	home = strings.TrimSpace(home)
	if !filepath.IsAbs(home) {
		return false
	}
	entries := readMCPServersCodexAt(filepath.Join(home, ".codex", "config.toml"), workspaceDir)
	return codexMCPToolServerAmbiguous(entries, toolServer)
}

func codexMCPToolServerAmbiguous(entries []MCPServerEntry, toolServer string) bool {
	toolServer = strings.TrimSpace(toolServer)
	if toolServer == "" {
		return false
	}
	first := ""
	for _, entry := range entries {
		if MCPToolServerName("codex", entry.Name) != toolServer {
			continue
		}
		if first != "" && first != entry.Name {
			return true
		}
		first = entry.Name
	}
	return false
}

// MCPToolServerName is the server segment an agent puts in the MCP tool
// names its hooks see (mcp__<server>__<tool>). Codex turns every character
// other than an ASCII letter, digit or underscore into "_", so a server
// configured as acme-notes reaches the hook as acme_notes (GAP-0939); Claude
// Code keeps "-" as well. Other connectors keep the name.
func MCPToolServerName(connector, name string) string {
	var keepDash bool
	switch normalizeConnectorKey(connector) {
	case "codex":
	case "claudecode":
		keepDash = true
	default:
		return name
	}
	return strings.Map(func(r rune) rune {
		if r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || keepDash && r == '-' {
			return r
		}
		return '_'
	}, name)
}

// SameMCPToolServer reports whether a tool call's server name, as the
// connector's hook sees it, names the configured server.
func SameMCPToolServer(connector, configured, toolServer string) bool {
	configured, toolServer = strings.TrimSpace(configured), strings.TrimSpace(toolServer)
	if configured == "" || toolServer == "" {
		return false
	}
	return configured == toolServer || MCPToolServerName(connector, configured) == toolServer
}

// lookupMCPToolServer finds the entry a tool call's server name names: the
// exact name, or else the one configured name whose tool-name form it is.
// Two names with the same form are ambiguous and match neither, so the call
// keeps the name it came with and an approval never moves between them.
func lookupMCPToolServer(connector string, entries []MCPServerEntry, name string) (MCPServerEntry, bool) {
	for _, entry := range entries {
		if entry.Name == name {
			return entry, true
		}
	}
	var found MCPServerEntry
	for _, entry := range entries {
		if !SameMCPToolServer(connector, entry.Name, name) {
			continue
		}
		if found.Name != "" && found.Name != entry.Name {
			return MCPServerEntry{}, false
		}
		if found.Name == "" {
			found = entry
		}
	}
	return found, found.Name != ""
}

func (c *Config) readMCPServersForConnectorIn(connector, workspaceDir string) ([]MCPServerEntry, error) {
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
	case "kiro":
		return readMCPServersKiro(workspaceDir)
	case "devin":
		return readMCPServersDevin(workspaceDir)
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
		if c == nil {
			return nil, nil
		}
		return readMCPServersOpenClaw(c.Claw.ConfigFile)
	}
}

// ReadWatchedMCPServers returns the MCP servers the install watcher admits
// and rescans: every scope of each connector, tagged with the connector. For
// Claude Code that adds every project ~/.claude.json knows, with the servers
// 'claude mcp add' stored for it (local scope) and its .mcp.json (project
// scope), each tagged with the project: the gateway has no working folder,
// so these were never scanned (GAP-0405).
func (c *Config) ReadWatchedMCPServers(connectors []string) ([]MCPServerEntry, error) {
	var out []MCPServerEntry
	var firstErr error
	for _, name := range connectors {
		entries, err := c.ReadMCPServersForConnector(name)
		if err != nil && firstErr == nil {
			firstErr = err
		}
		for _, entry := range entries {
			entry.Connector = normalizeConnectorKey(name)
			out = append(out, entry)
		}
		if normalizeConnectorKey(name) == "claudecode" {
			out = append(out, claudeCodeProjectMCPServers()...)
		}
	}
	if len(out) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

// claudeCodeProjectMCPServers lists, for each project in the Claude Code
// state file, the local-scope servers stored there and the project .mcp.json.
func claudeCodeProjectMCPServers() []MCPServerEntry {
	data, err := os.ReadFile(claudeCodeMCPStatePath())
	if err != nil {
		return nil
	}
	var state map[string]any
	if json.Unmarshal(data, &state) != nil {
		return nil
	}
	return claudeStateProjectServers(state, func(project string) ([]byte, error) {
		return os.ReadFile(filepath.Join(project, ".mcp.json"))
	})
}

// ClaudeStateMCPServers lists the MCP servers a Claude Code state file
// (~/.claude.json) names: the user scope, the local scope of each project,
// and the .mcp.json of each project, which readProjectMCP returns (nil skips
// them). Entries are tagged claudecode; project servers carry their project.
// The managed Windows enumerator, which runs as LocalSystem, reads the state
// file for the gateway service, whose account cannot read it (GAP-0424).
func ClaudeStateMCPServers(data []byte, readProjectMCP func(project string) ([]byte, error)) ([]MCPServerEntry, error) {
	var state map[string]any
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	user, _ := readMCPFromAnyPaths(state, []string{"mcpServers"})
	out := make([]MCPServerEntry, 0, len(user))
	for _, entry := range dedupMCPEntries(user) {
		entry.Connector = "claudecode"
		out = append(out, entry)
	}
	return append(out, claudeStateProjectServers(state, readProjectMCP)...), nil
}

// claudeStateProjectServers lists the local-scope and .mcp.json servers of
// every project in a decoded Claude Code state file.
func claudeStateProjectServers(state map[string]any, readProjectMCP func(project string) ([]byte, error)) []MCPServerEntry {
	projectStates, _ := state["projects"].(map[string]any)
	projects := make([]string, 0, len(projectStates))
	for project := range projectStates {
		if filepath.IsAbs(project) {
			projects = append(projects, project)
		}
	}
	sort.Strings(projects)
	var out []MCPServerEntry
	for _, project := range projects {
		if raw, ok := projectStates[project].(map[string]any); ok {
			local, _ := readMCPFromAnyPaths(raw, []string{"mcpServers"})
			for _, entry := range local {
				entry.Connector, entry.Project, entry.SourceScope = "claudecode", filepath.Clean(project), "local"
				out = append(out, entry)
			}
		}
		if readProjectMCP == nil {
			continue
		}
		data, err := readProjectMCP(project)
		if err != nil {
			continue
		}
		if shared, err := parseDotMCPJSON(data); err == nil {
			for _, entry := range shared {
				entry.Connector, entry.Project, entry.SourceScope = "claudecode", filepath.Clean(project), "project"
				out = append(out, entry)
			}
		}
	}
	return out
}

// ReadUserMCPServersForConnector returns a sandbox harness's user-scope MCP
// servers only: neither the workspace-local registry nor a project's
// (.mcp.json, .codex/config.toml). A sandbox brings the user's own servers
// along; a repository's servers are governed by the sandbox pack's
// mcp.project_servers. Only claudecode and codex run in sandboxes.
func ReadUserMCPServersForConnector(connector string) ([]MCPServerEntry, error) {
	switch normalizeConnectorKey(connector) {
	case "claudecode":
		return readMCPServersClaudeCode("")
	case "codex":
		return readMCPServersCodex("")
	default:
		return nil, fmt.Errorf("no user-scope MCP inventory for connector %q", connector)
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

// ReadMCPFromDotMCPJSON is the exported wrapper around the internal
// `.mcp.json` reader so AI-discovery / signature-catalog callers can
// enumerate the servers declared inside a matched file without
// re-implementing the "wrapped in mcpServers vs bare map" fallback.
func ReadMCPFromDotMCPJSON(path string) ([]MCPServerEntry, error) {
	return readMCPFromDotMCPJSON(path)
}

// ReadMCPFromClaudeSettings is the exported wrapper around the
// Claude Code settings.json / .claude.json reader; input is a path to
// a JSON file with a top-level `mcpServers` map.
func ReadMCPFromClaudeSettings(path string) ([]MCPServerEntry, error) {
	return readMCPFromClaudeSettings(path)
}

// ReadMCPFromJSONCPaths reads the MCP servers found at each key chain of
// paths in a JSON or JSONC file (union). AI discovery uses it for the agent
// files whose servers are not a top-level mcpServers map: Amp's
// amp.mcpServers and OpenClaw's and ZeptoClaw's mcp.servers (GAP-1062).
func ReadMCPFromJSONCPaths(path string, paths ...[]string) ([]MCPServerEntry, error) {
	data, err := readMCPConfigFile(path, maxMCPConfigFileBytes)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal(jsonc.Strip(data), &doc); err != nil {
		return nil, err
	}
	return readMCPFromAnyPaths(doc, paths...)
}

// ReadMCPFromCodexConfigTOML is the exported wrapper around the
// Codex `~/.codex/config.toml` reader for callers that need to
// enumerate mcp_servers entries out of a TOML file.
func ReadMCPFromCodexConfigTOML(path string) ([]MCPServerEntry, error) {
	return readMCPFromCodexConfigTOML(path)
}

// ReadMCPFromYAMLPath is the exported wrapper around readMCPFromYAMLPath;
// each `paths` argument is a JSON-pointer-style chain of keys to walk
// (e.g. `[]string{"mcp", "servers"}`).
func ReadMCPFromYAMLPath(path string, paths ...[]string) ([]MCPServerEntry, error) {
	return readMCPFromYAMLPath(path, paths...)
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

// OpenClawConfigCandidates returns the openclaw.json paths whose presence
// marks OpenClaw as set up on this machine: claw.config_file and
// <claw.home_dir>/openclaw.json, with "~/" expanded and duplicates removed.
// With both keys empty it falls back to the loader default
// ~/.openclaw/openclaw.json. OpenClaw writes this file when it is onboarded,
// and its own gateway cannot start without it. Mirrors
// openclaw_presence.openclaw_config_candidates in the Python CLI.
func (c *Config) OpenClawConfigCandidates() []string {
	configFile, homeDir := "", ""
	if c != nil {
		configFile = strings.TrimSpace(c.Claw.ConfigFile)
		homeDir = strings.TrimSpace(c.Claw.HomeDir)
	}
	if configFile == "" && homeDir == "" {
		configFile = "~/.openclaw/openclaw.json"
	}
	raw := []string{configFile}
	if homeDir != "" {
		raw = append(raw, filepath.Join(expandPath(homeDir), "openclaw.json"))
	}
	out := make([]string, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for _, candidate := range raw {
		if candidate == "" {
			continue
		}
		candidate = filepath.Clean(expandPath(candidate))
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		out = append(out, candidate)
	}
	return out
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
	case "devin":
		configHome, err := devinConfigHome()
		if err != nil {
			return ""
		}
		return configHome
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
		if configured := openCodeEnvPath(os.Getenv("OPENCODE_CONFIG_DIR"), c.ConnectorWorkspaceDir()); configured != "" {
			return configured
		}
		// OpenCode keeps its default config under ~/.config/opencode/
		// (XDG-style); matches connector_paths.connector_home("opencode").
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
	case "kiro":
		// Kiro IDE and Kiro CLI share ~/.kiro; matches
		// connector_paths.connector_home("kiro") on the Python side. It used to
		// fall through to OpenClaw's home_dir, so Kiro's agent identity was
		// keyed on ~/.openclaw.
		return filepath.Join(home, ".kiro")
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
		dirs := make([]string, 0, 5)
		for _, layer := range gatewayconnector.CodexProjectLayerDirs(cwd) {
			dirs = append(dirs, filepath.Join(layer, ".agents", "skills"))
		}
		dirs = append(dirs, gatewayconnector.CodexPersonalSkillsPath())
		dirs = append(dirs, filepath.Join(c.ConnectorHomeDir("codex"), "skills"))
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
	case "devin":
		configHome, err := devinConfigHome()
		if err != nil {
			return nil
		}
		// Devin CLI and Devin Local share these roots; the pre-rename Devin
		// Desktop locations the vendor still loads are read-only extras.
		return dedupNonEmpty(append([]string{
			filepath.Join(configHome, "skills"),
			filepath.Join(home, ".agents", "skills"),
			workspaceJoin(cwd, ".devin", "skills"),
			workspaceJoin(cwd, ".agents", "skills"),
		}, legacyconnector.DesktopLegacySkillPaths(home, cwd)...))
	case "opencode", "omnigent", "kiro":
		// These connectors have no documented local skills surface (Kiro's
		// reusable context is steering docs and specs). Keep them isolated
		// from OpenClaw's skill directories: the install watcher creates the
		// folders it watches, so falling through would leave an empty
		// ~/.openclaw tree behind.
		return nil
	case "amp":
		return ampSkillDirs(home, cwd)
	case "antigravity":
		return dedupNonEmpty([]string{
			filepath.Join(home, ".gemini", "config", "skills"),
			workspaceJoin(cwd, ".agents", "skills"),
			workspaceJoin(cwd, ".agent", "skills"),
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
	case "cursor", "devin", "copilot", "openhands", "opencode", "omnigent", "kiro":
		return nil
	default:
		return c.pluginDirsOpenClaw()
	}
}

// --- Connector-specific MCP readers ---

func readMCPServersClaudeCode(workspaceDir string) ([]MCPServerEntry, error) {
	return readMCPServersClaudeCodeAt(claudeCodeMCPStatePath(),
		filepath.Join(connectorEnvHome("CLAUDE_CONFIG_DIR", ".claude"), "settings.json"), workspaceDir), nil
}

// readMCPServersClaudeCodeAt reads Claude Code's servers from its state
// file and settings.json at the given paths and the project .mcp.json.
func readMCPServersClaudeCodeAt(statePath, settingsPath, workspaceDir string) []MCPServerEntry {
	cwd := strings.TrimSpace(workspaceDir)

	var entries []MCPServerEntry
	local, user, stateErr := readMCPFromClaudeState(statePath, cwd)
	if stateErr == nil {
		// Claude's documented precedence is local, project, then user.
		// dedupMCPEntries is first-wins, so append the workspace-matched local
		// scope before either user registry.
		entries = append(entries, local...)
	}

	// A missing or malformed state file must not suppress a valid project
	// registry. Project discovery is explicit-workspace-only.
	if cwd != "" {
		mcpJSONPath := filepath.Join(cwd, ".mcp.json")
		if e, err := readMCPFromDotMCPJSON(mcpJSONPath); err == nil {
			entries = append(entries, e...)
		}
	}
	if stateErr == nil {
		entries = append(entries, user...)
	}

	// DefenseClaw 0.8.x wrote `mcp set` entries into settings.json. Keep that
	// block as the final, legacy layer: the state file Claude Code reads wins
	// a name, and the legacy block still fills names only it has (GAP-1340).
	if e, err := readMCPFromClaudeSettings(settingsPath); err == nil {
		entries = append(entries, e...)
	}

	return dedupMCPEntries(entries)
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

// claudeJSONScopes is the union shape of ~/.claude.json we care about: the
// user-scope `mcpServers` block and the per-project local-scope
// `projects.<path>.mcpServers` blocks. Split out so one read+unmarshal of the
// (often multi-megabyte) file is enough to cover both scopes.
type claudeJSONMCPServer struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
	URL     string            `json:"url"`
	Type    string            `json:"type"`
}

type claudeJSONScopes struct {
	MCPServers map[string]claudeJSONMCPServer `json:"mcpServers"`
	Projects   map[string]struct {
		MCPServers map[string]claudeJSONMCPServer `json:"mcpServers"`
	} `json:"projects"`
}

// parseClaudeJSONScopes unmarshals ~/.claude.json once and splits the two
// MCP-server scopes out. `user` is the top-level mcpServers map (user scope);
// `projects` is the flattened union of every projects.<path>.mcpServers block
// (local scope). Callers that already have the raw bytes should prefer this
// helper to the pair of ReadMCPFromClaudeSettings + ReadMCPFromClaudeJSONProjects
// wrappers, which each open and decode the file independently.
func parseClaudeJSONScopes(data []byte) (user, projects []MCPServerEntry, err error) {
	var doc claudeJSONScopes
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, nil, err
	}
	for name, s := range doc.MCPServers {
		user = append(user, MCPServerEntry{
			Name:      name,
			Command:   s.Command,
			Args:      s.Args,
			Env:       s.Env,
			URL:       s.URL,
			Transport: s.Type,
		})
	}
	for _, project := range doc.Projects {
		for name, s := range project.MCPServers {
			projects = append(projects, MCPServerEntry{
				Name:      name,
				Command:   s.Command,
				Args:      s.Args,
				Env:       s.Env,
				URL:       s.URL,
				Transport: s.Type,
			})
		}
	}
	return user, projects, nil
}

// ReadMCPFromClaudeJSONBothScopes is the exported single-read helper: it
// opens ~/.claude.json once and returns the union of user-scope
// (top-level mcpServers) and local-scope (projects.<path>.mcpServers)
// entries. Callers that need both scopes should prefer this over pairing
// ReadMCPFromClaudeSettings + ReadMCPFromClaudeJSONProjects, which would
// each read and decode the (often multi-megabyte) conversation-state file.
func ReadMCPFromClaudeJSONBothScopes(path string) ([]MCPServerEntry, error) {
	data, err := readMCPConfigFile(path, maxClaudeJSONConfigBytes)
	if err != nil {
		return nil, err
	}
	user, projects, err := parseClaudeJSONScopes(data)
	if err != nil {
		return nil, err
	}
	return append(user, projects...), nil
}

func readMCPServersCodex(workspaceDir string) ([]MCPServerEntry, error) {
	return readMCPServersCodexAt(filepath.Join(connectorEnvHome("CODEX_HOME", ".codex"), "config.toml"), workspaceDir), nil
}

// readMCPServersCodexAt reads Codex's servers from the user config.toml at
// userPath and the project layers of workspaceDir.
func readMCPServersCodexAt(userPath, workspaceDir string) []MCPServerEntry {
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
	if e, err := ReadMCPFromCodexUserConfigTOML(userPath); err == nil {
		entries = append(entries, e...)
	}
	return dedupMCPEntries(entries)
}

func annotateCodexMCPEntries(entries []MCPServerEntry, source, scope string, trustRequired bool) []MCPServerEntry {
	for index := range entries {
		entries[index].Source = source
		entries[index].SourceScope = scope
		entries[index].TrustRequired = trustRequired
	}
	return entries
}

// ReadUserMCPServersForHome reads the user-scope MCP registries that
// connectorName keeps under home, for a managed gateway that watches every
// enrolled user: Codex's config.toml, Claude Code's .claude.json and
// settings.json, Devin's mcp_config.json in that user's roaming AppData
// (GAP-1237) and Kiro's ~/.kiro/settings/mcp.json (GAP-1233). Unreadable
// files are skipped; each entry carries the connector. Other connectors list
// none.
func ReadUserMCPServersForHome(connectorName, home string) []MCPServerEntry {
	home = strings.TrimSpace(home)
	if home == "" {
		return nil
	}
	var entries []MCPServerEntry
	switch normalizeConnectorKey(connectorName) {
	case "codex":
		if e, err := ReadMCPFromCodexUserConfigTOML(filepath.Join(home, ".codex", "config.toml")); err == nil {
			entries = append(entries, e...)
		}
	case "claudecode":
		if _, user, err := readMCPFromClaudeState(filepath.Join(home, ".claude.json"), ""); err == nil {
			entries = append(entries, user...)
		}
		if e, err := readMCPFromClaudeSettings(filepath.Join(home, ".claude", "settings.json")); err == nil {
			entries = append(entries, e...)
		}
	case "devin":
		// The service's own %APPDATA% is not the user's: resolve the
		// enrolled profile's.
		if e, err := ReadMCPFromDevinConfig(filepath.Join(devinConfigHomeFor(home), "mcp_config.json")); err == nil {
			entries = append(entries, e...)
		}
	case "kiro":
		entries = readMCPServersKiroAt(home, "")
	default:
		return nil
	}
	entries = dedupMCPEntries(entries)
	for index := range entries {
		entries[index].Connector = normalizeConnectorKey(connectorName)
	}
	return entries
}

// ReadMCPFromCodexUserConfigTOML reads a path that the caller has already
// resolved as a Codex user-scope config. Only this provenance-aware entry point
// can promote an exact built-in table shape to Bundled; project and generic
// TOML readers intentionally leave the same name/URL scan-eligible.
func ReadMCPFromCodexUserConfigTOML(path string) ([]MCPServerEntry, error) {
	entries, err := readMCPFromCodexConfigTOML(path)
	if err != nil {
		return nil, err
	}
	entries = annotateCodexMCPEntries(entries, path, "user", false)
	for index := range entries {
		entries[index].Bundled = entries[index].codexBuiltinShape
	}
	return entries, nil
}

const maxCodexInventoryConfigBytes = 1 << 20

// Bounds of one MCP config read. Claude Code's ~/.claude.json carries its
// conversation state and runs to tens of MiB; the other files are small.
const (
	maxMCPConfigFileBytes    = 16 << 20
	maxClaudeJSONConfigBytes = 256 << 20
)

// readMCPConfigFile reads one agent MCP config. A link is followed, as
// dotfile managers link these files, but only a regular file within limit is
// read and a FIFO never blocks the open: AI discovery reads these files in
// every user's home, and a config linked to /dev/zero would grow the scan
// until the host ran out of memory (GAP-0694).
func readMCPConfigFile(path string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0) // #nosec G304 -- agent MCP config path
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("MCP config %s is not a regular file", path)
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("MCP config %s exceeds %d bytes", path, limit)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("MCP config %s exceeds %d bytes", path, limit)
	}
	return data, nil
}

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
	if err := gatewayconnector.ParseCodexTOML(data, &doc); err != nil {
		return nil, err
	}
	var rawDoc struct {
		MCPServers map[string]map[string]any `toml:"mcp_servers"`
	}
	if err := gatewayconnector.ParseCodexTOML(data, &rawDoc); err != nil {
		return nil, err
	}
	out := make([]MCPServerEntry, 0, len(doc.MCPServers))
	for name, cfg := range doc.MCPServers {
		out = append(out, MCPServerEntry{
			Name:              name,
			Command:           cfg.Command,
			Args:              cfg.Args,
			Env:               cfg.Env,
			URL:               cfg.URL,
			Transport:         cfg.Transport,
			codexBuiltinShape: isCodexBuiltinMCPShape(name, rawDoc.MCPServers[name]),
		})
	}
	return out, nil
}

func isCodexBuiltinMCPShape(name string, raw map[string]any) bool {
	if name != "openaiDeveloperDocs" || len(raw) != 1 {
		return false
	}
	url, ok := raw["url"].(string)
	return ok && url == "https://developers.openai.com/mcp"
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
	// Hermes loads top-level mcp_servers (GAP-1591); mcp.servers is where
	// older DefenseClaw builds wrote, kept readable so it can be removed.
	return readMCPFromYAMLPath(hermespath.ConfigPath(), []string{"mcp_servers"}, []string{"mcp", "servers"}, []string{"mcpServers"})
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

// Kiro keeps global and workspace MCP registrations in separate mcp.json
// files. Keep both scopes, including same-name entries, so admission can
// evaluate each registration independently.
func readMCPServersKiro(workspaceDir string) ([]MCPServerEntry, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	return readMCPServersKiroAt(home, workspaceDir), nil
}

func readMCPServersKiroAt(home, workspaceDir string) []MCPServerEntry {
	userPath := filepath.Join(home, ".kiro", "settings", "mcp.json")
	paths := []struct{ path, scope, project string }{}
	if workspace := strings.TrimSpace(workspaceDir); workspace != "" {
		projectPath := filepath.Join(workspace, ".kiro", "settings", "mcp.json")
		if projectReal, err := filepath.EvalSymlinks(projectPath); err == nil {
			if userReal, err := filepath.EvalSymlinks(userPath); err == nil && projectReal == userReal {
				projectPath = ""
			}
		} else if filepath.Clean(projectPath) == filepath.Clean(userPath) {
			projectPath = ""
		}
		if projectPath != "" {
			paths = append(paths, struct{ path, scope, project string }{projectPath, "project", filepath.Clean(workspace)})
		}
	}
	paths = append(paths, struct{ path, scope, project string }{userPath, "user", ""})
	var entries []MCPServerEntry
	for _, source := range paths {
		found, err := readMCPFromDotMCPJSON(source.path)
		if err != nil {
			continue
		}
		for _, entry := range found {
			entry.Source = source.path
			entry.SourceScope = source.scope
			entry.Project = source.project
			entries = append(entries, entry)
		}
	}
	return entries
}

const maxDevinInventoryConfigBytes int64 = 4 << 20

// readMCPServersDevin reads Devin's canonical MCP registries in effective
// precedence order. Project-local settings win over project settings, and both
// win over the lifecycle-bound user registry. A workspace is consulted only
// when the operator pinned one in DefenseClaw configuration; the gateway's own
// working directory is never inferred.
func readMCPServersDevin(workspaceDir string) ([]MCPServerEntry, error) {
	configHome, err := devinConfigHome()
	if err != nil {
		return nil, err
	}

	var entries []MCPServerEntry
	if workspace := strings.TrimSpace(workspaceDir); workspace != "" {
		for _, name := range []string{"mcp_config.local.json", "mcp_config.json"} {
			if found, readErr := ReadMCPFromDevinConfig(filepath.Join(workspace, ".devin", name)); readErr == nil {
				entries = append(entries, found...)
			}
		}
	}
	if found, readErr := ReadMCPFromDevinConfig(filepath.Join(configHome, "mcp_config.json")); readErr == nil {
		entries = append(entries, found...)
	}
	return dedupMCPEntries(entries), nil
}

// devinConfigHome resolves the exact user configuration root used by the
// current lifecycle. Native Setup supplies its Known-Folder result through the
// DefenseClaw-only binding; source installs use Devin's documented platform
// defaults.
func devinConfigHome() (string, error) {
	if configured, exists := envvars.Lookup("DEFENSECLAW_DEVIN_CONFIG_HOME"); exists {
		if configured == "" || strings.TrimSpace(configured) != configured ||
			strings.ContainsAny(configured, "\x00\r\n") ||
			!filepath.IsAbs(configured) || filepath.Clean(configured) != configured {
			return "", fmt.Errorf("DEFENSECLAW_DEVIN_CONFIG_HOME is not an absolute normalized path")
		}
		return configured, nil
	}

	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return "", fmt.Errorf("Devin user home is unavailable")
	}
	if runtime.GOOS == "windows" {
		if appData := strings.TrimSpace(os.Getenv("APPDATA")); appData != "" {
			return filepath.Join(filepath.Clean(appData), "devin"), nil
		}
	}
	return devinConfigHomeFor(home), nil
}

// devinConfigHomeFor is Devin's default user configuration root in home.
func devinConfigHomeFor(home string) string {
	if runtime.GOOS == "windows" {
		return filepath.Join(home, "AppData", "Roaming", "devin")
	}
	return filepath.Join(home, ".config", "devin")
}

// ReadMCPFromDevinConfig reads one canonical Devin mcp_config.json file using
// the same bounded, stable-file boundary as other native inventory readers.
// Both Devin's wrapped mcpServers shape and its compatible top-level map are
// accepted.
func ReadMCPFromDevinConfig(path string) ([]MCPServerEntry, error) {
	data, ok := gatewayconnector.ReadStableInventoryFile(path, maxDevinInventoryConfigBytes)
	if !ok {
		return nil, fmt.Errorf("Devin MCP config is unavailable, unstable, unsafe, or exceeds %d bytes: %s", maxDevinInventoryConfigBytes, path)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	if _, wrapped := raw["mcpServers"]; wrapped {
		return readMCPFromAnyPaths(raw, []string{"mcpServers"})
	}
	return readMCPFromAnyPaths(map[string]any{"mcpServers": raw}, []string{"mcpServers"})
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
	data, err := readMCPConfigFile(path, maxMCPConfigFileBytes)
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
	data, err := readMCPConfigFile(path, maxMCPConfigFileBytes)
	if err != nil {
		return nil, err
	}
	return parseDotMCPJSON(data)
}

// parseDotMCPJSON reads the servers of an .mcp.json document.
func parseDotMCPJSON(data []byte) ([]MCPServerEntry, error) {
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
	paths := ampUserSettingsPaths(home, workspace, workspaceFirst)
	managed := ampManagedSettingsPath()
	if workspaceFirst {
		return dedupNonEmpty(append([]string{managed}, paths...))
	}
	return dedupNonEmpty(append(paths, managed))
}

func ampUserSettingsPaths(home, workspace string, workspaceFirst bool) []string {
	user := []string{preferredAMPSettingsPath(
		filepath.Join(home, ".config", "amp", "settings.json"),
		filepath.Join(home, ".config", "amp", "settings.jsonc"),
	)}
	project := []string{preferredAMPSettingsPath(
		workspaceJoin(workspace, ".amp", "settings.json"),
		workspaceJoin(workspace, ".amp", "settings.jsonc"),
	)}
	if workspaceFirst {
		return dedupNonEmpty(append(project, user...))
	}
	return dedupNonEmpty(append(user, project...))
}

func ampSkillDirs(home, workspace string) []string {
	return ampSkillDirsFromSettings(
		home,
		workspace,
		ampSettingsPaths(home, workspace, false),
	)
}

func ampSkillDirsFromSettings(home, workspace string, settingsPaths []string) []string {
	disableClaude := false
	var extraPath string
	// Read user then workspace so the documented workspace override wins.
	for _, path := range settingsPaths {
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
	data = jsonc.Strip(data)
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return doc, nil
}

func readMCPFromClaudeSettings(path string) ([]MCPServerEntry, error) {
	data, err := readMCPConfigFile(path, maxMCPConfigFileBytes)
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
	return readMCPServersAMPFromHome(
		home,
		cwd,
		ampSettingsPaths(home, cwd, true),
		ampSettingsPaths(home, cwd, false),
	)
}

// ReadMCPServersAMPUnderHome reads Amp's standard user settings and
// skill-bundled MCP files below an explicitly selected home. Shared managed
// settings and project layers are intentionally outside this per-user view.
func ReadMCPServersAMPUnderHome(home string) ([]MCPServerEntry, error) {
	home = strings.TrimSpace(home)
	if home == "" {
		return nil, nil
	}
	return readMCPServersAMPFromHome(
		home,
		"",
		ampUserSettingsPaths(home, "", true),
		ampUserSettingsPaths(home, "", false),
	)
}

// ReadMCPFromAmpSettings reads the MCP servers of one Amp settings file
// (settings.json, settings.jsonc or managed-settings.json). Amp keeps them
// under the flat key amp.mcpServers, where `amp mcp add` writes them; AI
// Discovery read these files with the Claude Code reader, which looks for a
// top-level mcpServers, and so listed none of them (GAP-1062).
func ReadMCPFromAmpSettings(path string) ([]MCPServerEntry, error) {
	doc, err := readJSONObjectJSONC(path)
	if err != nil {
		return nil, err
	}
	return readMCPFromAnyPaths(doc, []string{"amp.mcpServers"})
}

func readMCPServersAMPFromHome(home, workspace string, settingsPaths, skillSettingsPaths []string) ([]MCPServerEntry, error) {
	var entries []MCPServerEntry

	for _, path := range settingsPaths {
		doc, err := readJSONObjectJSONC(path)
		if err != nil {
			continue
		}
		if found, err := readMCPFromAnyPaths(doc, []string{"amp.mcpServers"}); err == nil {
			entries = append(entries, found...)
		}
	}

	for _, skillRoot := range ampSkillDirsFromSettings(home, workspace, skillSettingsPaths) {
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
