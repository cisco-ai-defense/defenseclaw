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
// branch — Codex reads ./.mcp.json and Codex only. We point CWD
// at a temp dir with a known .mcp.json and confirm we get its entries
// back via the no-arg ReadMCPServers (i.e. dispatcher works).
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

	entries, err := cfg.ReadMCPServers()
	if err != nil {
		t.Fatalf("ReadMCPServers: %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "hello" || entries[0].Command != "echo" {
		t.Errorf("entries = %+v, want [{hello echo …}]", entries)
	}
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
