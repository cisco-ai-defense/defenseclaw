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

package inventory

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestDetectSkills_EnumeratesChildBasenames pins the fix for the
// reported bug: for skills the wire payload's `basenames` used to
// carry just the parent-directory name (`["skills"]`) because
// signalFromPath stamped filepath.Base(<parent dir>). The detector
// must now enumerate the immediate children of the skills directory
// and surface those names (e.g. `["skill-a", "skill-b", "skills"]`)
// so downstream consumers see the actual skill inventory.
func TestDetectSkills_EnumeratesChildBasenames(t *testing.T) {
	tmp := t.TempDir()
	skillsDir := filepath.Join(tmp, ".claude", "skills")
	if err := os.MkdirAll(filepath.Join(skillsDir, "skill-a"), 0o700); err != nil {
		t.Fatalf("mkdir skill-a: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(skillsDir, "skill-b"), 0o700); err != nil {
		t.Fatalf("mkdir skill-b: %v", err)
	}
	// A dotfile that must be filtered out.
	if err := os.WriteFile(filepath.Join(skillsDir, ".DS_Store"), []byte("junk"), 0o600); err != nil {
		t.Fatalf("write DS_Store: %v", err)
	}

	sig := AISignature{
		ID:                 "claudecode",
		Name:               "Claude Code",
		Vendor:             "Anthropic",
		Category:           SignalSupportedConnector,
		SupportedConnector: "claudecode",
		SkillPaths:         []string{"~/.claude/skills"},
	}
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled: true,
		Mode:    "enhanced",
		DataDir: filepath.Join(tmp, "data"),
		HomeDir: tmp,
	}, []AISignature{sig})
	cleanupPreparedDiscoveryService(t, svc)

	signals := svc.detectSkills()
	if len(signals) != 1 {
		t.Fatalf("detectSkills: got %d signals, want 1: %+v", len(signals), signals)
	}
	got := signals[0]
	if got.Category != SignalSkill {
		t.Fatalf("category = %q, want %q", got.Category, SignalSkill)
	}
	if !slices.Contains(got.Basenames, "skill-a") || !slices.Contains(got.Basenames, "skill-b") {
		t.Fatalf("basenames missing skill-a / skill-b: %v", got.Basenames)
	}
	if slices.Contains(got.Basenames, ".DS_Store") {
		t.Fatalf("basenames must filter .DS_Store: %v", got.Basenames)
	}
	// Parent-directory row is retained so PathHashes still
	// identifies the surface. There must be >= 3 rows total
	// (parent + 2 skills) after filtering.
	if len(got.Evidence) < 3 {
		t.Fatalf("evidence rows = %d, want >= 3: %+v", len(got.Evidence), got.Evidence)
	}
}

// TestDetectPlugins_EnumeratesChildBasenames — same fix, plugins.
func TestDetectPlugins_EnumeratesChildBasenames(t *testing.T) {
	tmp := t.TempDir()
	pluginsDir := filepath.Join(tmp, ".codex", "plugins")
	for _, name := range []string{"plugin-x", "plugin-y", "plugin-z"} {
		if err := os.MkdirAll(filepath.Join(pluginsDir, name), 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", name, err)
		}
	}
	sig := AISignature{
		ID:                 "codex",
		Name:               "Codex",
		Vendor:             "OpenAI",
		Category:           SignalSupportedConnector,
		SupportedConnector: "codex",
		PluginPaths:        []string{"~/.codex/plugins"},
	}
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled: true,
		Mode:    "enhanced",
		DataDir: filepath.Join(tmp, "data"),
		HomeDir: tmp,
	}, []AISignature{sig})
	cleanupPreparedDiscoveryService(t, svc)

	signals := svc.detectPlugins()
	if len(signals) != 1 {
		t.Fatalf("detectPlugins: got %d signals, want 1", len(signals))
	}
	got := signals[0]
	for _, want := range []string{"plugin-x", "plugin-y", "plugin-z"} {
		if !slices.Contains(got.Basenames, want) {
			t.Fatalf("basenames missing %q: %v", want, got.Basenames)
		}
	}
}

// TestDetectMCPPaths_EnumeratesServerNames_MCPJSON pins the MCP half
// of the fix. Before this change `basenames` for an OpenHands-style
// `~/.openhands/mcp.json` was just `["mcp.json"]` — no way to tell
// which MCP servers were declared inside. Post-fix each declared
// server name shows up in Basenames too, alongside the config-file
// basename that the file-identity evidence row keeps.
func TestDetectMCPPaths_EnumeratesServerNames_MCPJSON(t *testing.T) {
	tmp := t.TempDir()
	mcpPath := filepath.Join(tmp, ".openhands", "mcp.json")
	body := `{
  "mcpServers": {
    "filesystem": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]},
    "github":     {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"]}
  }
}`
	if err := os.MkdirAll(filepath.Dir(mcpPath), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(mcpPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write mcp.json: %v", err)
	}

	sig := AISignature{
		ID:                 "openhands",
		Name:               "OpenHands",
		Vendor:             "All Hands AI",
		Category:           SignalSupportedConnector,
		SupportedConnector: "openhands",
		MCPPaths:           []string{"~/.openhands/mcp.json"},
	}
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled: true,
		Mode:    "enhanced",
		DataDir: filepath.Join(tmp, "data"),
		HomeDir: tmp,
	}, []AISignature{sig})
	cleanupPreparedDiscoveryService(t, svc)

	signals := svc.detectMCPPaths()
	if len(signals) != 1 {
		t.Fatalf("detectMCPPaths: got %d signals, want 1", len(signals))
	}
	got := signals[0]
	if got.Category != SignalMCPServer {
		t.Fatalf("category = %q, want %q", got.Category, SignalMCPServer)
	}
	for _, want := range []string{"mcp.json", "filesystem", "github"} {
		if !slices.Contains(got.Basenames, want) {
			t.Fatalf("basenames missing %q: %v", want, got.Basenames)
		}
	}
	// One evidence row per declared server should exist, tagged
	// with the mcp_server evidence type so downstream policy can
	// distinguish "config file exists" from "servers declared".
	var serverRows int
	for _, ev := range got.Evidence {
		if ev.Type == "mcp_server" {
			serverRows++
		}
	}
	if serverRows != 2 {
		t.Fatalf("mcp_server evidence rows = %d, want 2: %+v", serverRows, got.Evidence)
	}
}

// TestDetectMCPPaths_MalformedFileStillEmitsFileSignal ensures a
// malformed MCP config never *suppresses* the discovery signal —
// the endpoint has an MCP surface even if the parser can't crack
// its contents. Parse failure just means Basenames doesn't gain
// server names.
func TestDetectMCPPaths_MalformedFileStillEmitsFileSignal(t *testing.T) {
	tmp := t.TempDir()
	mcpPath := filepath.Join(tmp, ".openhands", "mcp.json")
	if err := os.MkdirAll(filepath.Dir(mcpPath), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(mcpPath, []byte(`{ this is not json`), 0o600); err != nil {
		t.Fatalf("write malformed mcp.json: %v", err)
	}
	sig := AISignature{
		ID:                 "openhands",
		Name:               "OpenHands",
		Vendor:             "All Hands AI",
		Category:           SignalSupportedConnector,
		SupportedConnector: "openhands",
		MCPPaths:           []string{"~/.openhands/mcp.json"},
	}
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled: true,
		Mode:    "enhanced",
		DataDir: filepath.Join(tmp, "data"),
		HomeDir: tmp,
	}, []AISignature{sig})
	cleanupPreparedDiscoveryService(t, svc)

	signals := svc.detectMCPPaths()
	if len(signals) != 1 {
		t.Fatalf("detectMCPPaths: got %d signals, want 1", len(signals))
	}
	if !slices.Contains(signals[0].Basenames, "mcp.json") {
		t.Fatalf("expected file basename in basenames despite parse failure: %v", signals[0].Basenames)
	}
}

// TestDetectMCPPaths_EnumeratesServerNames_ClaudeSettings pins the
// settings.json-shaped MCP config path (Claude Code / Claude Desktop).
// The parser dispatch must recognize the filename and use the
// `mcpServers` reader instead of falling through to a JSONC/TOML path.
func TestDetectMCPPaths_EnumeratesServerNames_ClaudeSettings(t *testing.T) {
	tmp := t.TempDir()
	settings := filepath.Join(tmp, ".claude", "settings.json")
	body := `{
  "mcpServers": {
    "context7":   {"command": "npx", "args": ["-y", "@upstash/context7-mcp"]},
    "sequential": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-sequential-thinking"]}
  }
}`
	if err := os.MkdirAll(filepath.Dir(settings), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(settings, []byte(body), 0o600); err != nil {
		t.Fatalf("write settings.json: %v", err)
	}
	sig := AISignature{
		ID:                 "claudecode",
		Name:               "Claude Code",
		Vendor:             "Anthropic",
		Category:           SignalSupportedConnector,
		SupportedConnector: "claudecode",
		MCPPaths:           []string{"~/.claude/settings.json"},
	}
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled: true,
		Mode:    "enhanced",
		DataDir: filepath.Join(tmp, "data"),
		HomeDir: tmp,
	}, []AISignature{sig})
	cleanupPreparedDiscoveryService(t, svc)

	signals := svc.detectMCPPaths()
	if len(signals) != 1 {
		t.Fatalf("detectMCPPaths: got %d signals, want 1", len(signals))
	}
	got := signals[0]
	for _, want := range []string{"settings.json", "context7", "sequential"} {
		if !slices.Contains(got.Basenames, want) {
			t.Fatalf("basenames missing %q: %v", want, got.Basenames)
		}
	}
}

// TestSanitizeBasenameValue documents the sanitizer's contract: it
// mirrors the validator ValidateSanitizedAIDiscoveryReport enforces
// on Basenames, and OS-metadata dotfiles are filtered so they never
// pollute the wire payload.
func TestSanitizeBasenameValue(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"skill-a", "skill-a"},
		{"  skill-b  ", "skill-b"},
		{"", ""},
		{"has/slash", ""},
		{"has\\backslash", ""},
		{".DS_Store", ""},
		{"Thumbs.db", ""},
		{"desktop.ini", ""},
		{strings.Repeat("x", 300), ""},
		{"skill\nnewline", ""},
		{"skill\x00null", ""},
		{"skill\x1bescape", ""},
		{"legit-name-with_underscores.and.dots", "legit-name-with_underscores.and.dots"},
	}
	for _, tc := range cases {
		if got := sanitizeBasenameValue(tc.in); got != tc.want {
			t.Errorf("sanitizeBasenameValue(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
