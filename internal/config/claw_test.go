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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestActiveConnector_Precedence pins the resolution order:
//
//	guardrail.connector  >  claw.mode  >  "openclaw"
//
// Whitespace-only values must not "win" the fallback chain — they are
// treated as unset so a stray "  " in YAML can't silently mask a real
// claw.mode setting.
func TestActiveConnector_Precedence(t *testing.T) {
	tests := []struct {
		name      string
		connector string
		clawMode  ClawMode
		want      string
	}{
		{"explicit_connector_wins", "codex", "openclaw", "codex"},
		{"connector_overrides_mode", "claudecode", "openclaw", "claudecode"},
		{"empty_connector_uses_mode", "", "openclaw", "openclaw"},
		{"whitespace_connector_uses_mode", "  ", "zeptoclaw", "zeptoclaw"},
		{"both_empty_defaults_openclaw", "", "", "openclaw"},
		{"whitespace_mode_defaults_openclaw", "", "  ", "openclaw"},
		{"trims_connector", "  codex  ", "openclaw", "codex"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{}
			cfg.Guardrail.Connector = tt.connector
			cfg.Claw.Mode = tt.clawMode
			if got := cfg.activeConnector(); got != tt.want {
				t.Errorf("activeConnector() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestActiveConnector_NilSafe(t *testing.T) {
	var cfg *Config
	if got := cfg.activeConnector(); got != "openclaw" {
		t.Errorf("nil cfg activeConnector() = %q, want openclaw", got)
	}
}

// TestSkillDirs_DispatchesViaConnector ensures the no-arg SkillDirs()
// honors guardrail.connector. This is the contract sidecar runWatcher
// and InstalledSkillCandidates rely on: callers that don't want to
// know about connectors get the right paths automatically.
func TestSkillDirs_DispatchesViaConnector(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("UserHomeDir unavailable: %v", err)
	}

	tests := []struct {
		connector string
		mustHave  string
	}{
		{"codex", filepath.Join(home, ".codex", "skills")},
		{"claudecode", filepath.Join(home, ".claude", "skills")},
		{"zeptoclaw", filepath.Join(home, ".zeptoclaw", "skills")},
	}

	for _, tt := range tests {
		t.Run(tt.connector, func(t *testing.T) {
			cfg := &Config{}
			cfg.Guardrail.Connector = tt.connector
			cfg.Claw.HomeDir = "/tmp/should-be-ignored"

			dirs := cfg.SkillDirs()
			if !containsPath(dirs, tt.mustHave) {
				t.Errorf("SkillDirs() for %s did not return %q; got %v", tt.connector, tt.mustHave, dirs)
			}
			openclawDir := filepath.Join("/tmp/should-be-ignored", "skills")
			if containsPath(dirs, openclawDir) {
				t.Errorf("SkillDirs() for %s leaked OpenClaw path %q; got %v", tt.connector, openclawDir, dirs)
			}
		})
	}
}

// TestPluginDirs_DispatchesViaConnector mirrors SkillDirs dispatch
// for the plugin/extension surface.
func TestPluginDirs_DispatchesViaConnector(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("UserHomeDir unavailable: %v", err)
	}

	tests := []struct {
		connector string
		want      string
	}{
		{"codex", filepath.Join(home, ".codex", "plugins")},
		{"claudecode", filepath.Join(home, ".claude", "plugins")},
		{"zeptoclaw", filepath.Join(home, ".zeptoclaw", "plugins")},
	}

	for _, tt := range tests {
		t.Run(tt.connector, func(t *testing.T) {
			cfg := &Config{}
			cfg.Guardrail.Connector = tt.connector
			cfg.Claw.HomeDir = "/tmp/should-be-ignored"

			dirs := cfg.PluginDirs()
			if len(dirs) != 1 {
				t.Fatalf("PluginDirs() for %s = %v, want 1 dir", tt.connector, dirs)
			}
			if dirs[0] != tt.want {
				t.Errorf("PluginDirs()[0] for %s = %q, want %q", tt.connector, dirs[0], tt.want)
			}
		})
	}
}

// TestSkillDirs_FallsBackToOpenClaw confirms the legacy default —
// when guardrail.connector is unset, SkillDirs() must keep returning
// OpenClaw paths (workspace/skills + claw_home/skills) so existing
// deployments don't drift.
func TestSkillDirs_FallsBackToOpenClaw(t *testing.T) {
	homeDir := t.TempDir()
	cfg := &Config{}
	cfg.Claw.HomeDir = homeDir
	cfg.Claw.ConfigFile = filepath.Join(homeDir, "openclaw.json")

	dirs := cfg.SkillDirs()
	wantSkillsDir := filepath.Join(homeDir, "skills")
	wantWorkspace := filepath.Join(homeDir, "workspace", "skills")

	if !containsPath(dirs, wantSkillsDir) {
		t.Errorf("SkillDirs() missing %q; got %v", wantSkillsDir, dirs)
	}
	if !containsPath(dirs, wantWorkspace) {
		t.Errorf("SkillDirs() missing %q; got %v", wantWorkspace, dirs)
	}
}

// TestPluginDirs_FallsBackToOpenClaw is the parallel guarantee for
// plugins — must continue producing claw_home/extensions when no
// connector is configured.
func TestPluginDirs_FallsBackToOpenClaw(t *testing.T) {
	cfg := &Config{}
	cfg.Claw.HomeDir = "/tmp/legacy-oc-home"

	dirs := cfg.PluginDirs()
	want := "/tmp/legacy-oc-home/extensions"
	if len(dirs) != 1 || dirs[0] != want {
		t.Errorf("PluginDirs() = %v, want [%q]", dirs, want)
	}
}

// TestSkillDirsForConnector_DefaultArmDoesNotRecurse ensures the
// "openclaw" / unknown branch of SkillDirsForConnector calls the
// private skillDirsOpenClaw helper directly. Before S1.2 it called
// c.SkillDirs() which now dispatches polymorphically — that would
// have caused infinite recursion when guardrail.connector was set
// to a non-built-in name.
func TestSkillDirsForConnector_DefaultArmDoesNotRecurse(t *testing.T) {
	homeDir := t.TempDir()
	cfg := &Config{}
	cfg.Guardrail.Connector = "future-connector"
	cfg.Claw.HomeDir = homeDir
	cfg.Claw.ConfigFile = filepath.Join(homeDir, "openclaw.json")

	dirs := cfg.SkillDirsForConnector("openclaw")
	if !containsPath(dirs, filepath.Join(homeDir, "skills")) {
		t.Errorf("SkillDirsForConnector(openclaw) did not include OpenClaw paths: %v", dirs)
	}

	dirs = cfg.SkillDirsForConnector("totally-unknown-connector")
	if !containsPath(dirs, filepath.Join(homeDir, "skills")) {
		t.Errorf("SkillDirsForConnector(unknown) did not fall back to OpenClaw: %v", dirs)
	}
}

func TestPluginDirsForConnector_DefaultArmDoesNotRecurse(t *testing.T) {
	cfg := &Config{}
	cfg.Guardrail.Connector = "future-connector"
	cfg.Claw.HomeDir = "/tmp/foo"

	dirs := cfg.PluginDirsForConnector("openclaw")
	if len(dirs) != 1 || dirs[0] != "/tmp/foo/extensions" {
		t.Errorf("PluginDirsForConnector(openclaw) = %v, want [/tmp/foo/extensions]", dirs)
	}
}

// TestReadMCPServers_DispatchesViaConnector hooks into the codex
// branch — Codex reads <workspace>/.mcp.json and Codex only. We pin
// claw.workspace_dir to a temp dir with a known .mcp.json and confirm
// we get its entries back via the no-arg ReadMCPServers (i.e. the
// dispatcher honors the configured workspace, not the daemon cwd).
func TestReadMCPServers_DispatchesViaConnector(t *testing.T) {
	tmp := t.TempDir()
	mcp := map[string]any{
		"mcpServers": map[string]any{
			"hello": map[string]any{
				"command": "echo",
				"args":    []string{"hi"},
			},
		},
	}
	data, err := json.Marshal(mcp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	mcpPath := filepath.Join(tmp, ".mcp.json")
	if err := os.WriteFile(mcpPath, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Isolate HOME so the real user's ~/.codex/config.toml (which may
	// register global MCP servers like playwright) doesn't leak into
	// the assertion below — Codex layers the global TOML table with
	// the project-local ./.mcp.json we wrote above.
	t.Setenv("HOME", tmp)

	prev, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	cfg := &Config{}
	cfg.Guardrail.Connector = "codex"
	cfg.Claw.WorkspaceDir = tmp

	entries, err := cfg.ReadMCPServers()
	if err != nil {
		t.Fatalf("ReadMCPServers: %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "hello" || entries[0].Command != "echo" {
		t.Errorf("entries = %+v, want [{hello echo …}]", entries)
	}
}

func TestReadMCPServers_UsesPinnedWorkspaceForProjectMCP(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	workspace := filepath.Join(tmp, "repo")
	daemonCWD := filepath.Join(tmp, ".defenseclaw")
	for _, dir := range []string{
		home,
		filepath.Join(workspace, ".github"),
		filepath.Join(daemonCWD, ".github"),
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	t.Setenv("HOME", home)

	writeMCP := func(path, name string) {
		t.Helper()
		data, err := json.Marshal(map[string]any{
			"mcpServers": map[string]any{
				name: map[string]any{"command": "echo", "args": []string{name}},
			},
		})
		if err != nil {
			t.Fatalf("marshal %s: %v", name, err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	writeMCP(filepath.Join(workspace, ".github", "mcp.json"), "pinned")
	writeMCP(filepath.Join(daemonCWD, ".github", "mcp.json"), "daemon-cwd")

	prev, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })
	if err := os.Chdir(daemonCWD); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	cfg := &Config{
		DataDir: daemonCWD,
		Claw:    ClawConfig{WorkspaceDir: workspace},
	}
	cfg.Guardrail.Connector = "copilot"

	entries, err := cfg.ReadMCPServers()
	if err != nil {
		t.Fatalf("ReadMCPServers: %v", err)
	}
	if !hasMCPEntry(entries, "pinned") {
		t.Fatalf("entries = %+v, want pinned workspace MCP server", entries)
	}
	if hasMCPEntry(entries, "daemon-cwd") {
		t.Fatalf("entries = %+v, should not read daemon cwd MCP server", entries)
	}
}

func hasMCPEntry(entries []MCPServerEntry, name string) bool {
	for _, entry := range entries {
		if entry.Name == name {
			return true
		}
	}
	return false
}

// containsPath is intentionally local — strings.Contains over a slice.
// Keeps this file independent of unexported helpers in claw.go.
func containsPath(paths []string, want string) bool {
	for _, p := range paths {
		if strings.EqualFold(p, want) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Root 1 — opencode / antigravity must NOT fall through to OpenClaw
// ---------------------------------------------------------------------------

// TestReadMCPServersForConnector_OpenCode pins that opencode reads its
// own opencode.json `mcp` map (full read parity, mcp.md M2), splitting
// the fused command argv and surfacing remote servers by URL.
func TestReadMCPServersForConnector_OpenCode(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	ocDir := filepath.Join(home, ".config", "opencode")
	if err := os.MkdirAll(ocDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := `{
	  "mcp": {
	    "fs": {"type": "local", "command": ["npx", "-y", "fs-mcp"], "environment": {"TOKEN": "x"}},
	    "api": {"type": "remote", "url": "https://example.com/mcp"}
	  }
	}`
	if err := os.WriteFile(filepath.Join(ocDir, "opencode.json"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	c := &Config{}
	entries, err := c.ReadMCPServersForConnector("opencode")
	if err != nil {
		t.Fatalf("ReadMCPServersForConnector(opencode): %v", err)
	}
	if !hasMCPEntry(entries, "fs") || !hasMCPEntry(entries, "api") {
		t.Fatalf("entries = %+v, want fs + api", entries)
	}
	for _, e := range entries {
		switch e.Name {
		case "fs":
			if e.Command != "npx" || len(e.Args) != 2 || e.Args[0] != "-y" || e.Args[1] != "fs-mcp" {
				t.Errorf("fs = %+v, want command=npx args=[-y fs-mcp]", e)
			}
			if e.Env["TOKEN"] != "x" || e.Transport != "local" {
				t.Errorf("fs = %+v, want env TOKEN=x, transport=local", e)
			}
		case "api":
			if e.URL != "https://example.com/mcp" || e.Transport != "remote" {
				t.Errorf("api = %+v, want url + transport=remote", e)
			}
		}
	}
}

// TestReadMCPServersForConnector_OpenCodeNeverReadsOpenClaw is the
// Root-1 regression: opencode must read its own config, never
// ~/.openclaw/openclaw.json, even when OpenClaw has servers and
// opencode has none.
func TestReadMCPServersForConnector_OpenCodeNeverReadsOpenClaw(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	clawDir := filepath.Join(home, ".openclaw")
	if err := os.MkdirAll(clawDir, 0o700); err != nil {
		t.Fatal(err)
	}
	clawCfg := `{"mcp": {"servers": {"leaked": {"command": "do-not-show"}}}}`
	clawPath := filepath.Join(clawDir, "openclaw.json")
	if err := os.WriteFile(clawPath, []byte(clawCfg), 0o600); err != nil {
		t.Fatal(err)
	}

	c := &Config{}
	c.Claw.ConfigFile = clawPath
	entries, err := c.ReadMCPServersForConnector("opencode")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if hasMCPEntry(entries, "leaked") {
		t.Fatalf("opencode leaked OpenClaw's server: %+v", entries)
	}
	if len(entries) != 0 {
		t.Fatalf("entries = %+v, want empty (no opencode.json present)", entries)
	}
}

// TestReadMCPServersForConnector_AntigravityReturnsNil pins N1: Go must
// give antigravity nil (like Python), not OpenClaw's servers.
func TestReadMCPServersForConnector_AntigravityReturnsNil(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	clawDir := filepath.Join(home, ".openclaw")
	if err := os.MkdirAll(clawDir, 0o700); err != nil {
		t.Fatal(err)
	}
	clawPath := filepath.Join(clawDir, "openclaw.json")
	if err := os.WriteFile(clawPath, []byte(`{"mcp":{"servers":{"leaked":{"command":"x"}}}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	c := &Config{}
	c.Claw.ConfigFile = clawPath
	entries, err := c.ReadMCPServersForConnector("antigravity")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("antigravity entries = %+v, want nil (never OpenClaw)", entries)
	}
}

// TestSkillPluginDirs_OpenCodeAntigravityEmpty pins that the skill and
// plugin dispatchers give opencode/antigravity an empty set rather than
// falling through to the OpenClaw layout (claw.go:515/577 root).
func TestSkillPluginDirs_OpenCodeAntigravityEmpty(t *testing.T) {
	cfg := &Config{}
	cfg.Claw.HomeDir = "/tmp/should-not-appear"
	cfg.Claw.ConfigFile = "/tmp/should-not-appear/openclaw.json"
	for _, conn := range []string{"opencode", "antigravity"} {
		if dirs := cfg.SkillDirsForConnector(conn); len(dirs) != 0 {
			t.Errorf("SkillDirsForConnector(%s) = %v, want empty", conn, dirs)
		}
		if dirs := cfg.PluginDirsForConnector(conn); len(dirs) != 0 {
			t.Errorf("PluginDirsForConnector(%s) = %v, want empty", conn, dirs)
		}
	}
}

// TestConnectorHomeDir_OpenCodeAntigravity pins the home-dir parity with
// Python connector_home: opencode → ~/.config/opencode, antigravity →
// ~/.gemini/antigravity-cli, neither the OpenClaw home_dir (claw.go:406).
func TestConnectorHomeDir_OpenCodeAntigravity(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	cfg := &Config{}
	cfg.Claw.HomeDir = "/tmp/openclaw-home"

	if got, want := cfg.ConnectorHomeDir("opencode"), filepath.Join(home, ".config", "opencode"); got != want {
		t.Errorf("ConnectorHomeDir(opencode) = %q, want %q", got, want)
	}
	if got, want := cfg.ConnectorHomeDir("antigravity"), filepath.Join(home, ".gemini", "antigravity-cli"); got != want {
		t.Errorf("ConnectorHomeDir(antigravity) = %q, want %q", got, want)
	}
	if got := cfg.ConnectorHomeDir("opencode"); strings.Contains(got, "openclaw-home") {
		t.Errorf("ConnectorHomeDir(opencode) leaked OpenClaw home: %q", got)
	}
}

// ---------------------------------------------------------------------------
// Root 3 (Go side) — phantom-openclaw primitive
// ---------------------------------------------------------------------------

// TestHasConnectorConfigured pins the Go mirror of Python's
// has_connector_configured() (mcp.md M1). It must distinguish a
// genuinely-unconfigured install from an explicit one — WITHOUT changing
// the activeConnector() "openclaw" floor that many call sites depend on.
func TestHasConnectorConfigured(t *testing.T) {
	var nilCfg *Config
	if nilCfg.HasConnectorConfigured() {
		t.Error("nil cfg must report no connector configured")
	}

	empty := &Config{}
	if empty.HasConnectorConfigured() {
		t.Error("all-empty config must NOT report a configured connector (phantom-openclaw root)")
	}
	// The floor is deliberately preserved — only the helper distinguishes
	// the phantom from a real install.
	if got := empty.activeConnector(); got != "openclaw" {
		t.Errorf("activeConnector() floor changed to %q; must stay openclaw", got)
	}

	withConn := &Config{}
	withConn.Guardrail.Connector = "opencode"
	if !withConn.HasConnectorConfigured() {
		t.Error("explicit guardrail.connector must report configured")
	}

	withMode := &Config{}
	withMode.Claw.Mode = "openclaw"
	if !withMode.HasConnectorConfigured() {
		t.Error("explicit claw.mode must report configured")
	}

	whitespace := &Config{}
	whitespace.Guardrail.Connector = "   "
	if whitespace.HasConnectorConfigured() {
		t.Error("whitespace-only connector must be treated as unset")
	}

	multi := &Config{}
	multi.Guardrail.Connectors = map[string]PerConnectorGuardrailConfig{"codex": {}}
	if !multi.HasConnectorConfigured() {
		t.Error("populated guardrail.connectors map must report configured")
	}
}
