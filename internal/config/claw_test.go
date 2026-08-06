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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
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
		{"codex", filepath.Join(home, ".agents", "skills")},
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
		{"codex", filepath.Join(home, ".codex", "plugins", "cache")},
		{"claudecode", filepath.Join(home, ".claude", "plugins", "cache")},
		{"zeptoclaw", filepath.Join(home, ".zeptoclaw", "plugins")},
	}

	for _, tt := range tests {
		t.Run(tt.connector, func(t *testing.T) {
			cfg := &Config{}
			cfg.Guardrail.Connector = tt.connector
			cfg.Claw.HomeDir = "/tmp/should-be-ignored"

			dirs := cfg.PluginDirs()
			if !containsPath(dirs, tt.want) {
				t.Errorf("PluginDirs() for %s = %v, missing %q", tt.connector, dirs, tt.want)
			}
		})
	}
}

// TestSkillDirs_FallsBackToOpenClaw confirms the legacy default —
// when guardrail.connector is unset, SkillDirs() must keep returning
// OpenClaw paths (workspace/skills + claw_home/skills) so existing
// deployments don't drift.
func TestConnectorHomesHonorClientOverrides(t *testing.T) {
	root := t.TempDir()
	codexHome := filepath.Join(root, "codex-home")
	claudeHome := filepath.Join(root, "claude-home")
	t.Setenv("CODEX_HOME", codexHome)
	t.Setenv("CLAUDE_CONFIG_DIR", claudeHome)

	cfg := &Config{}
	if got := cfg.ConnectorHomeDir("codex"); got != codexHome {
		t.Fatalf("Codex home = %q, want %q", got, codexHome)
	}
	if got := cfg.ConnectorHomeDir("claudecode"); got != claudeHome {
		t.Fatalf("Claude config dir = %q, want %q", got, claudeHome)
	}
	if got := cfg.ConnectorHomeDir("claude-code"); got != claudeHome {
		t.Fatalf("Claude alias config dir = %q, want %q", got, claudeHome)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("UserHomeDir unavailable: %v", err)
	}
	codexSkillDir := filepath.Join(home, ".agents", "skills")
	if got := cfg.SkillDirsForConnector("codex"); !containsPath(got, codexSkillDir) {
		t.Fatalf("Codex skill dirs = %v, want personal path %q", got, codexSkillDir)
	}
	if got := cfg.PluginDirsForConnector("claudecode")[0]; got != filepath.Join(claudeHome, "plugins", "cache") {
		t.Fatalf("Claude plugin dir = %q", got)
	}
	cfg.Guardrail.Connector = "claude_code"
	if got := cfg.PluginDirs()[0]; got != filepath.Join(claudeHome, "plugins", "cache") {
		t.Fatalf("active Claude alias plugin dir = %q", got)
	}
	pluginParent := filepath.Join(root, "plugin-parent")
	t.Setenv("CLAUDE_CODE_PLUGIN_CACHE_DIR", pluginParent)
	if got := cfg.PluginDirsForConnector("claudecode")[0]; got != filepath.Join(pluginParent, "cache") {
		t.Fatalf("Claude plugin override dir = %q", got)
	}
}

func TestClaudePluginDirsIncludeAncestorAndNestedSkillsRoots(t *testing.T) {
	repository := filepath.Join(t.TempDir(), "repo")
	launch := filepath.Join(repository, "apps", "web")
	nested := filepath.Join(launch, "packages", "ui", ".claude", "skills")
	if err := os.MkdirAll(filepath.Join(repository, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{}
	cfg.Claw.WorkspaceDir = launch
	dirs := cfg.PluginDirsForConnector("claudecode")
	for _, want := range []string{
		filepath.Join(repository, ".claude", "skills"),
		nested,
	} {
		if !containsPath(dirs, want) {
			t.Errorf("PluginDirsForConnector(claudecode) = %v, missing %q", dirs, want)
		}
	}
}

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
	home := filepath.Join(t.TempDir(), "legacy-oc-home")
	cfg := &Config{}
	cfg.Claw.HomeDir = home

	dirs := cfg.PluginDirs()
	want := filepath.Join(home, "extensions")
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
	home := filepath.Join(t.TempDir(), "foo")
	cfg := &Config{}
	cfg.Guardrail.Connector = "future-connector"
	cfg.Claw.HomeDir = home

	dirs := cfg.PluginDirsForConnector("openclaw")
	want := filepath.Join(home, "extensions")
	if len(dirs) != 1 || dirs[0] != want {
		t.Errorf("PluginDirsForConnector(openclaw) = %v, want [%s]", dirs, want)
	}
}

// TestReadMCPServers_DispatchesViaConnector hooks into the Codex
// branch. Codex reads the project .codex/config.toml [mcp_servers] table. We pin
// claw.workspace_dir to a temp dir with a known project config and confirm
// we get its entries back via the no-arg ReadMCPServers (i.e. the
// dispatcher honors the configured workspace, not the daemon cwd).
func TestReadMCPServers_DispatchesViaConnector(t *testing.T) {
	tmp := t.TempDir()
	projectConfigDir := filepath.Join(tmp, ".codex")
	if err := os.MkdirAll(projectConfigDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	mcpPath := filepath.Join(projectConfigDir, "config.toml")
	if err := os.WriteFile(mcpPath, []byte(`
[mcp_servers.hello]
command = "echo"
args = ["hi"]
`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Isolate HOME so the real user's ~/.codex/config.toml (which may
	// register global MCP servers like playwright) doesn't leak into
	// the assertion below.
	testenv.SetHome(t, tmp)

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
	if entries[0].Source != mcpPath || entries[0].SourceScope != "project" || !entries[0].TrustRequired {
		t.Errorf("project metadata = %+v, want source/project/trust-required", entries[0])
	}
}

func TestWindsurfInventoryUsesPersistedBoundUserHome(t *testing.T) {
	root := t.TempDir()
	bound := filepath.Join(root, "bound-profile")
	ambient := filepath.Join(root, "ambient-profile")
	workspace := filepath.Join(root, "repo")
	testenv.SetHome(t, ambient)
	t.Setenv("WINDSURF_USER_HOME", bound)

	for _, item := range []struct {
		home string
		name string
	}{
		{home: bound, name: "bound"},
		{home: ambient, name: "ambient"},
	} {
		dir := filepath.Join(item.home, ".codeium", "windsurf")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		body := fmt.Sprintf(`{"mcpServers":{"%s":{"command":"%s-mcp"}}}`, item.name, item.name)
		if err := os.WriteFile(filepath.Join(dir, "mcp_config.json"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	guessed := filepath.Join(bound, ".codeium", "windsurf", "mcp.json")
	if err := os.WriteFile(guessed, []byte(`{"mcpServers":{"guessed":{"command":"guessed-mcp"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{Claw: ClawConfig{WorkspaceDir: workspace}}
	if got, want := cfg.ConnectorHomeDir("windsurf"), filepath.Join(bound, ".codeium", "windsurf"); got != want {
		t.Fatalf("ConnectorHomeDir(windsurf) = %q, want %q", got, want)
	}
	wantSkills := []string{
		filepath.Join(bound, ".codeium", "windsurf", "skills"),
		filepath.Join(bound, ".agents", "skills"),
		filepath.Join(workspace, ".windsurf", "skills"),
		filepath.Join(workspace, ".agents", "skills"),
	}
	if got := cfg.SkillDirsForConnector("windsurf"); len(got) != len(wantSkills) {
		t.Fatalf("SkillDirsForConnector(windsurf) = %v, want %v", got, wantSkills)
	} else {
		for _, want := range wantSkills {
			if !containsPath(got, want) {
				t.Fatalf("SkillDirsForConnector(windsurf) = %v, missing %q", got, want)
			}
		}
	}
	entries, err := cfg.ReadMCPServersForConnector("windsurf")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name != "bound" || entries[0].Command != "bound-mcp" {
		t.Fatalf("Windsurf MCP entries = %+v, want only bound profile", entries)
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
	testenv.SetHome(t, home)

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

func TestReadMCPServersClaudeCodeLocalProjectUserPrecedence(t *testing.T) {
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	root := t.TempDir()
	home := filepath.Join(root, "home")
	workspace := filepath.Join(root, "workspace")
	otherWorkspace := filepath.Join(root, "other")
	for _, dir := range []string{home, workspace, otherWorkspace} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	testenv.SetHome(t, home)

	state := map[string]any{
		"projects": map[string]any{
			filepath.Join(workspace, "."): map[string]any{
				"mcpServers": map[string]any{
					"shared":     map[string]any{"command": "local-command"},
					"local-only": map[string]any{"command": "local-only-command"},
				},
			},
			otherWorkspace: map[string]any{
				"mcpServers": map[string]any{
					"other-local": map[string]any{"command": "must-not-appear"},
				},
			},
		},
		"mcpServers": map[string]any{
			"shared":    map[string]any{"command": "user-command"},
			"user-only": map[string]any{"command": "user-only-command"},
		},
	}
	stateData, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), stateData, 0o600); err != nil {
		t.Fatal(err)
	}
	project := map[string]any{
		"mcpServers": map[string]any{
			"shared":       map[string]any{"command": "project-command"},
			"project-only": map[string]any{"command": "project-only-command"},
		},
	}
	projectData, err := json.Marshal(project)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, ".mcp.json"), projectData, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{Claw: ClawConfig{WorkspaceDir: workspace}}
	cfg.Guardrail.Connector = "claudecode"
	entries, err := cfg.ReadMCPServers()
	if err != nil {
		t.Fatal(err)
	}
	got := mcpEntriesByName(entries)
	if len(got) != 4 {
		t.Fatalf("entries = %+v, want four local/project/user entries", entries)
	}
	if got["shared"].Command != "local-command" {
		t.Fatalf("shared = %+v, want local scope to win", got["shared"])
	}
	for _, name := range []string{"local-only", "project-only", "user-only"} {
		if _, ok := got[name]; !ok {
			t.Errorf("entries = %+v, missing %q", entries, name)
		}
	}
	if _, ok := got["other-local"]; ok {
		t.Fatalf("entries = %+v, attributed a different workspace's local MCP", entries)
	}
}

func TestReadMCPServersClaudeCodeDoesNotInferWorkspaceFromCWD(t *testing.T) {
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	root := t.TempDir()
	home := filepath.Join(root, "home")
	workspace := filepath.Join(root, "workspace")
	for _, dir := range []string{home, workspace} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	testenv.SetHome(t, home)
	stateData, err := json.Marshal(map[string]any{
		"projects": map[string]any{
			workspace: map[string]any{
				"mcpServers": map[string]any{
					"local-only": map[string]any{"command": "must-not-appear"},
				},
			},
		},
		"mcpServers": map[string]any{
			"user-only": map[string]any{"command": "user-command"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), stateData, 0o600); err != nil {
		t.Fatal(err)
	}
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(previous) })
	if err := os.Chdir(workspace); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{}
	cfg.Guardrail.Connector = "claudecode"
	entries, err := cfg.ReadMCPServers()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name != "user-only" {
		t.Fatalf("entries = %+v, want only user scope", entries)
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

func mcpEntriesByName(entries []MCPServerEntry) map[string]MCPServerEntry {
	out := make(map[string]MCPServerEntry, len(entries))
	for _, entry := range entries {
		out[entry.Name] = entry
	}
	return out
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
	testenv.SetHome(t, home)
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

func TestReadMCPServersOpenCode_V11810PrecedenceJSONCAndDisabled(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	t.Setenv("OPENCODE_CONFIG", "")
	t.Setenv("OPENCODE_CONFIG_DIR", "")
	t.Setenv("OPENCODE_CONFIG_CONTENT", "")
	globalDir := filepath.Join(home, ".config", "opencode")
	if err := os.MkdirAll(globalDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(globalDir, "config.json"), []byte(`{
		// global layer
		"mcp": {"shared": {"type": "local", "command": ["global"}},},
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	explicit := filepath.Join(home, "explicit.jsonc")
	if err := os.WriteFile(explicit, []byte(`{"mcp":{"shared":{"command":["explicit"]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPENCODE_CONFIG", explicit)
	workspace := filepath.Join(home, "workspace")
	projectDir := filepath.Join(workspace, ".opencode")
	if err := os.MkdirAll(projectDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "opencode.json"), []byte(`{"mcp":{"shared":{"command":["project"]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "opencode.jsonc"), []byte(`{"mcp":{"shared":{"command":["project-directory"]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	homeComponent := filepath.Join(home, ".opencode")
	if err := os.MkdirAll(homeComponent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(homeComponent, "opencode.json"), []byte(`{"mcp":{"shared":{"command":["home-directory"]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	customDir := filepath.Join(home, "custom")
	if err := os.MkdirAll(customDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(customDir, "opencode.json"), []byte(`{"mcp":{"shared":{"command":["custom-directory"]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPENCODE_CONFIG_DIR", customDir)
	t.Setenv("OPENCODE_CONFIG_CONTENT", `{"mcp":{"shared":{"enabled":false}}}`)

	entries, err := readMCPServersOpenCode(workspace)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %+v, want one merged server", entries)
	}
	entry := entries[0]
	if entry.Command != "custom-directory" || !entry.Disabled {
		t.Fatalf("entry = %+v, want custom-directory preserved and disabled", entry)
	}
	if entry.Source != "OPENCODE_CONFIG_CONTENT" || entry.SourceScope != "inline" {
		t.Fatalf("provenance = (%q, %q), want inline content", entry.Source, entry.SourceScope)
	}

	resolution := resolveOpenCodeConfig(workspace)
	positions := map[string]int{}
	for index, layer := range resolution.Layers {
		if _, exists := positions[layer.Scope]; !exists {
			positions[layer.Scope] = index
		}
	}
	if !(positions["project-directory"] < positions["home-directory"] &&
		positions["home-directory"] < positions["custom-directory"] &&
		positions["custom-directory"] < positions["inline"]) {
		t.Fatalf("layer positions = %+v, want project < home < custom < inline", positions)
	}
	var remote, managed bool
	for _, source := range resolution.Unverified {
		remote = remote || source.Scope == "remote"
		managed = managed || source.Scope == "managed-enterprise"
	}
	if !remote || !managed {
		t.Fatalf("unverified sources = %+v, want remote and managed-enterprise", resolution.Unverified)
	}
}

// TestReadMCPServersForConnector_OpenCodeNeverReadsOpenClaw is the
// Root-1 regression: opencode must read its own config, never
// ~/.openclaw/openclaw.json, even when OpenClaw has servers and
// opencode has none.
func TestReadMCPServersForConnector_OpenCodeNeverReadsOpenClaw(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
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

func TestReadMCPServersForConnector_AntigravityReadsNativeMCP(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	workspace := filepath.Join(home, "repo")
	if err := os.MkdirAll(filepath.Join(home, ".gemini", "config"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(workspace, ".agents"), 0o700); err != nil {
		t.Fatal(err)
	}

	global := `{
	  "mcpServers": {
	    "remote-server-url": {
	      "serverUrl": "https://mcp.example.com/mcp/",
	      "headers": {"Authorization": "Bearer ${TOKEN}"},
	      "authProviderType": "oauth",
	      "oauth": {"scopes": ["repo"]},
	      "disabled": true,
	      "disabledTools": ["unsafe_tool"]
	    },
	    "remote-url": {"url": "https://compat.example.com/mcp/"},
	    "local": {
	      "command": "node",
	      "args": ["server.js", "--stdio"],
	      "env": {"TOKEN": "redacted"},
	      "cwd": "/workspace/project"
	    }
	  }
	}`
	if err := os.WriteFile(filepath.Join(home, ".gemini", "config", "mcp_config.json"), []byte(global), 0o600); err != nil {
		t.Fatal(err)
	}
	workspaceMCP := `{"mcpServers":{"workspace-local":{"command":"python","args":["-m","mcp_server"]}}}`
	if err := os.WriteFile(filepath.Join(workspace, ".agents", "mcp_config.json"), []byte(workspaceMCP), 0o600); err != nil {
		t.Fatal(err)
	}

	c := &Config{}
	c.Claw.WorkspaceDir = workspace
	entries, err := c.ReadMCPServersForConnector("antigravity")
	if err != nil {
		t.Fatalf("ReadMCPServersForConnector(antigravity): %v", err)
	}
	byName := mcpEntriesByName(entries)

	if got := byName["remote-server-url"].URL; got != "https://mcp.example.com/mcp/" {
		t.Fatalf("remote-server-url URL=%q", got)
	}
	remote := byName["remote-server-url"]
	if remote.Headers["Authorization"] != "Bearer ${TOKEN}" || remote.AuthProviderType != "oauth" || !remote.Disabled {
		t.Fatalf("remote-server-url metadata = %+v", remote)
	}
	if len(remote.DisabledTools) != 1 || remote.DisabledTools[0] != "unsafe_tool" {
		t.Fatalf("remote-server-url disabled tools = %v", remote.DisabledTools)
	}
	if scopes, _ := remote.OAuth["scopes"].([]any); len(scopes) != 1 || scopes[0] != "repo" {
		t.Fatalf("remote-server-url oauth = %#v", remote.OAuth)
	}
	if got := byName["remote-url"].URL; got != "https://compat.example.com/mcp/" {
		t.Fatalf("remote-url URL=%q", got)
	}
	local := byName["local"]
	if local.Command != "node" || len(local.Args) != 2 || local.Args[0] != "server.js" || local.Args[1] != "--stdio" {
		t.Fatalf("local entry = %+v, want command node args [server.js --stdio]", local)
	}
	if local.Env["TOKEN"] != "redacted" {
		t.Fatalf("local env = %v", local.Env)
	}
	if local.CWD != "/workspace/project" {
		t.Fatalf("local cwd = %q", local.CWD)
	}
	if got := byName["workspace-local"].Command; got != "python" {
		t.Fatalf("workspace-local command=%q; entries=%+v", got, entries)
	}
}

func TestReadMCPServersForConnector_AntigravityRequiresPinnedWorkspace(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	workspace := filepath.Join(home, "repo")
	if err := os.MkdirAll(filepath.Join(workspace, ".agents"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, ".agents", "mcp_config.json"), []byte(`{"mcpServers":{"workspace-only":{"command":"x"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	c := &Config{}
	entries, err := c.ReadMCPServersForConnector("antigravity")
	if err != nil {
		t.Fatalf("ReadMCPServersForConnector(antigravity): %v", err)
	}
	if hasMCPEntry(entries, "workspace-only") {
		t.Fatalf("antigravity read workspace MCP without a pinned workspace: %+v", entries)
	}
}

func TestReadMCPServersForConnector_AntigravityMissingAndMalformedSafeNoOpenClawFallback(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	clawDir := filepath.Join(home, ".openclaw")
	if err := os.MkdirAll(clawDir, 0o700); err != nil {
		t.Fatal(err)
	}
	clawPath := filepath.Join(clawDir, "openclaw.json")
	if err := os.WriteFile(clawPath, []byte(`{"mcp":{"servers":{"leaked":{"command":"x"}}}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{}
	cfg.Claw.ConfigFile = clawPath
	entries, err := cfg.ReadMCPServersForConnector("antigravity")
	if err != nil {
		t.Fatalf("missing antigravity config returned error: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("missing antigravity config entries = %+v, want empty without OpenClaw fallback", entries)
	}

	agyDir := filepath.Join(home, ".gemini", "config")
	if err := os.MkdirAll(agyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(agyDir, "mcp_config.json"), []byte(`{"mcpServers":`), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err = cfg.ReadMCPServersForConnector("antigravity")
	if err != nil {
		t.Fatalf("malformed antigravity config returned error: %v", err)
	}
	if hasMCPEntry(entries, "leaked") || len(entries) != 0 {
		t.Fatalf("malformed antigravity config entries = %+v, want empty without OpenClaw fallback", entries)
	}
}

// TestSkillPluginDirs_OpenCodeEmptyAntigravityNativePaths pins that
// opencode remains bridge-plugin-only while Antigravity exposes its own
// documented skill and plugin discovery roots. Neither connector may fall
// through to OpenClaw paths.
func TestSkillPluginDirs_OpenCodeEmptyAntigravityNativePaths(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	workspace := filepath.Join(home, "repo")
	cfg := &Config{}
	cfg.Claw.HomeDir = "/tmp/should-not-appear"
	cfg.Claw.ConfigFile = "/tmp/should-not-appear/openclaw.json"
	cfg.Claw.WorkspaceDir = workspace

	if dirs := cfg.SkillDirsForConnector("opencode"); len(dirs) != 0 {
		t.Errorf("SkillDirsForConnector(opencode) = %v, want empty", dirs)
	}
	if dirs := cfg.PluginDirsForConnector("opencode"); len(dirs) != 0 {
		t.Errorf("PluginDirsForConnector(opencode) = %v, want empty", dirs)
	}

	skillDirs := cfg.SkillDirsForConnector("antigravity")
	for _, want := range []string{
		filepath.Join(home, ".gemini", "config", "skills"),
		filepath.Join(workspace, ".agents", "skills"),
		filepath.Join(workspace, ".agent", "skills"),
	} {
		if !containsPath(skillDirs, want) {
			t.Errorf("SkillDirsForConnector(antigravity) missing %q; got %v", want, skillDirs)
		}
	}
	pluginDirs := cfg.PluginDirsForConnector("antigravity")
	for _, want := range []string{
		filepath.Join(home, ".gemini", "config", "plugins"),
		filepath.Join(home, ".gemini", "antigravity-cli", "plugins"),
		filepath.Join(workspace, ".agents", "plugins"),
		filepath.Join(workspace, "_agents", "plugins"),
	} {
		if !containsPath(pluginDirs, want) {
			t.Errorf("PluginDirsForConnector(antigravity) missing %q; got %v", want, pluginDirs)
		}
	}
	for _, dirs := range [][]string{skillDirs, pluginDirs} {
		for _, dir := range dirs {
			if strings.Contains(dir, "should-not-appear") {
				t.Fatalf("antigravity path leaked OpenClaw home: %v", dirs)
			}
		}
	}
}

// TestConnectorHomeDir_OpenCodeAntigravity pins the home-dir parity with
// Python connector_home: opencode → ~/.config/opencode, antigravity →
// ~/.gemini/antigravity-cli, neither the OpenClaw home_dir (claw.go:406).
func TestConnectorHomeDir_OpenCodeAntigravity(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
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

func TestConnectorHomeDir_OmnigentConfigHome(t *testing.T) {
	home := t.TempDir()
	configHome := filepath.Join(home, "isolated-omnigent")
	testenv.SetHome(t, home)
	t.Setenv("OMNIGENT_CONFIG_HOME", configHome)
	cfg := &Config{}

	if got := cfg.ConnectorHomeDir("omnigent"); got != configHome {
		t.Fatalf("ConnectorHomeDir(omnigent) = %q, want %q", got, configHome)
	}
}

func TestAMPReadsJSONCSettingsAndSkillBundledMCPWithPrecedence(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	workspace := filepath.Join(home, "repo")
	for _, dir := range []string{
		filepath.Join(home, ".config", "amp"),
		filepath.Join(home, ".config", "agents", "skills", "browser"),
		filepath.Join(workspace, ".amp"),
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	userSettings := `{
	  // Amp uses dotted top-level setting names.
	  "amp.mcpServers": {
	    "user-only": {"command": "user-mcp", "args": ["--stdio"],},
	    "shared": {"command": "user-shared"}
	  },
	}`
	if err := os.WriteFile(filepath.Join(home, ".config", "amp", "settings.jsonc"), []byte(userSettings), 0o600); err != nil {
		t.Fatal(err)
	}
	workspaceSettings := `{"amp.mcpServers":{
	  "shared":{"command":"workspace-shared"},
	  "remote":{"url":"https://example.test/mcp","headers":{"Authorization":"${TOKEN}"}}
	}}`
	if err := os.WriteFile(filepath.Join(workspace, ".amp", "settings.json"), []byte(workspaceSettings), 0o600); err != nil {
		t.Fatal(err)
	}
	skillMCP := `{
	  "skill-only":{"command":"skill-mcp"},
	  "shared":{"command":"skill-must-not-win"}
	}`
	if err := os.WriteFile(filepath.Join(home, ".config", "agents", "skills", "browser", "mcp.json"), []byte(skillMCP), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{}
	cfg.Claw.WorkspaceDir = workspace
	entries, err := cfg.ReadMCPServersForConnector("amp")
	if err != nil {
		t.Fatal(err)
	}
	byName := mcpEntriesByName(entries)
	for _, want := range []string{"user-only", "shared", "remote", "skill-only"} {
		if _, ok := byName[want]; !ok {
			t.Fatalf("entries=%+v missing %q", entries, want)
		}
	}
	if got := byName["shared"].Command; got != "workspace-shared" {
		t.Fatalf("shared command=%q want workspace override", got)
	}
	if got := byName["remote"].Headers["Authorization"]; got != "${TOKEN}" {
		t.Fatalf("remote header=%q", got)
	}
}

func TestAMPSkillAndPluginDiscoveryHonorsSettings(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	workspace := filepath.Join(home, "repo")
	custom := filepath.Join(home, "team-skills")
	pluginSkills := filepath.Join(home, ".config", "amp", "plugins", "team-plugin", "skills")
	for _, dir := range []string{
		filepath.Join(workspace, ".amp"),
		custom,
		pluginSkills,
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	settings := `{
	  "amp.skills.path": "` + strings.ReplaceAll(custom, `\`, `\\`) + `",
	  "amp.skills.disableClaudeCodeSkills": true
	}`
	if err := os.WriteFile(filepath.Join(workspace, ".amp", "settings.jsonc"), []byte(settings), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{}
	cfg.Claw.WorkspaceDir = workspace
	skills := cfg.SkillDirsForConnector("amp")
	for _, want := range []string{
		filepath.Join(home, ".config", "agents", "skills"),
		filepath.Join(home, ".agents", "skills"),
		filepath.Join(home, ".config", "amp", "skills"),
		filepath.Join(workspace, ".agents", "skills"),
		custom,
		pluginSkills,
	} {
		if !containsPath(skills, want) {
			t.Errorf("Amp skills=%v missing %q", skills, want)
		}
	}
	for _, path := range skills {
		if strings.Contains(path, filepath.Join(".claude", "skills")) {
			t.Fatalf("Claude skill path present despite disable setting: %v", skills)
		}
	}
	plugins := cfg.PluginDirsForConnector("amp")
	for _, want := range []string{
		filepath.Join(home, ".config", "amp", "plugins"),
		filepath.Join(workspace, ".amp", "plugins"),
	} {
		if !containsPath(plugins, want) {
			t.Errorf("Amp plugins=%v missing %q", plugins, want)
		}
	}
	if got, want := cfg.ConnectorHomeDir("amp"), filepath.Join(home, ".config", "amp"); got != want {
		t.Fatalf("ConnectorHomeDir(amp)=%q want %q", got, want)
	}
}

func TestAMPClaudePluginCacheSkillsFollowDisableSetting(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	workspace := filepath.Join(home, "repo")
	settingsDir := filepath.Join(workspace, ".amp")
	cachedSkills := filepath.Join(
		home,
		".claude",
		"plugins",
		"cache",
		"marketplace",
		"review-plugin",
		"1.2.3",
		"skills",
	)
	for _, dir := range []string{settingsDir, cachedSkills} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	if skills := ampSkillDirs(home, workspace); !containsPath(skills, cachedSkills) {
		t.Fatalf("Amp skills=%v missing Claude plugin-cache skills %q", skills, cachedSkills)
	}

	settings := `{"amp.skills.disableClaudeCodeSkills":true}`
	if err := os.WriteFile(filepath.Join(settingsDir, "settings.json"), []byte(settings), 0o600); err != nil {
		t.Fatal(err)
	}
	skills := ampSkillDirs(home, workspace)
	if containsPath(skills, cachedSkills) {
		t.Fatalf("Claude plugin-cache skills present despite disable setting: %v", skills)
	}
	for _, path := range skills {
		if strings.Contains(path, filepath.Join(".claude", "skills")) {
			t.Fatalf("Claude skill path present despite disable setting: %v", skills)
		}
	}
}

func TestAMPSettingsReaderRejectsSymlinkAndOversize(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(root, "target.json")
		link := filepath.Join(root, "settings.json")
		if err := os.WriteFile(
			target,
			[]byte(`{"amp.skills.disableClaudeCodeSkills":true}`),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		if _, err := readJSONObjectJSONC(link); err == nil {
			t.Fatal("Amp settings reader followed a symlink")
		}
	})

	t.Run("oversize", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "settings.json")
		if err := os.WriteFile(path, make([]byte, ampSettingsReadLimit+1), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readJSONObjectJSONC(path); err == nil {
			t.Fatalf("Amp settings reader accepted a file larger than %d bytes", ampSettingsReadLimit)
		}
	})
}

func TestAMPSkillSettingsPreferJSONAndFallBackToJSONC(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	configDir := filepath.Join(home, ".config", "amp")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	jsonSkills := filepath.Join(home, "json-skills")
	jsoncSkills := filepath.Join(home, "jsonc-skills")
	jsonSettings := `{
	  "amp.skills.path": "` + strings.ReplaceAll(jsonSkills, `\`, `\\`) + `",
	  "amp.skills.disableClaudeCodeSkills": true
	}`
	jsoncSettings := `{
	  "amp.skills.path": "` + strings.ReplaceAll(jsoncSkills, `\`, `\\`) + `",
	  "amp.skills.disableClaudeCodeSkills": false
	}`
	jsonPath := filepath.Join(configDir, "settings.json")
	jsoncPath := filepath.Join(configDir, "settings.jsonc")
	if err := os.WriteFile(jsonPath, []byte(jsonSettings), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(jsoncPath, []byte(jsoncSettings), 0o600); err != nil {
		t.Fatal(err)
	}

	skills := ampSkillDirs(home, "")
	if !containsPath(skills, jsonSkills) || containsPath(skills, jsoncSkills) {
		t.Fatalf("both settings files skills=%v; want JSON only", skills)
	}
	for _, path := range skills {
		if strings.Contains(path, filepath.Join(".claude", "skills")) {
			t.Fatalf("JSON disable setting did not win: %v", skills)
		}
	}

	if err := os.Remove(jsonPath); err != nil {
		t.Fatal(err)
	}
	skills = ampSkillDirs(home, "")
	if !containsPath(skills, jsoncSkills) || containsPath(skills, jsonSkills) {
		t.Fatalf("JSON absent skills=%v; want JSONC fallback only", skills)
	}
	if !containsPath(skills, filepath.Join(home, ".claude", "skills")) {
		t.Fatalf("JSONC fallback disable setting was not applied: %v", skills)
	}
}

func TestHermesSurfacesHonorHermesHome(t *testing.T) {
	hermesHome := filepath.Join(t.TempDir(), "Hermes Home")
	t.Setenv("HERMES_HOME", hermesHome)
	configPath := filepath.Join(hermesHome, "config.yaml")
	if err := os.MkdirAll(hermesHome, 0o700); err != nil {
		t.Fatal(err)
	}
	configYAML := []byte("mcp:\n  servers:\n    native-windows:\n      command: hermes-mcp\n")
	if err := os.WriteFile(configPath, configYAML, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{}
	if got := cfg.ConnectorHomeDir("hermes"); got != hermesHome {
		t.Errorf("ConnectorHomeDir(hermes) = %q, want %q", got, hermesHome)
	}
	if got, want := cfg.SkillDirsForConnector("hermes"), filepath.Join(hermesHome, "skills"); len(got) != 1 || got[0] != want {
		t.Errorf("SkillDirsForConnector(hermes) = %v, want [%q]", got, want)
	}
	plugins := cfg.PluginDirsForConnector("hermes")
	if want := filepath.Join(hermesHome, "plugins"); !containsPath(plugins, want) {
		t.Errorf("PluginDirsForConnector(hermes) = %v, missing %q", plugins, want)
	}
	entries, err := cfg.ReadMCPServersForConnector("hermes")
	if err != nil {
		t.Fatalf("ReadMCPServersForConnector(hermes): %v", err)
	}
	if got := mcpEntriesByName(entries)["native-windows"].Command; got != "hermes-mcp" {
		t.Fatalf("Hermes MCP command = %q, want hermes-mcp; entries=%+v", got, entries)
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
	whitespace.Guardrail.Connectors = map[string]PerConnectorGuardrailConfig{"   ": {}}
	if whitespace.HasConnectorConfigured() {
		t.Error("whitespace-only connector map key must be treated as unset")
	}

	multi := &Config{}
	multi.Guardrail.Connectors = map[string]PerConnectorGuardrailConfig{"codex": {}}
	if !multi.HasConnectorConfigured() {
		t.Error("populated guardrail.connectors map must report configured")
	}
}
