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
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// TestReadMCPFromCodexConfigTOML covers the bug fix where Codex's
// global MCP server registry (~/.codex/config.toml) was being silently
// ignored — `defenseclaw mcp list` for a Codex install only saw
// project-local ./.mcp.json, hiding every globally-registered server.
func TestReadMCPFromCodexConfigTOML(t *testing.T) {
	t.Run("happy_path_dotted_table", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.toml")
		body := `
[mcp_servers.fs]
command = "node"
args = ["/opt/fs.js"]

[mcp_servers.fs.env]
TOKEN = "redacted"

[mcp_servers.search]
command = "search-mcp"
args = ["--port", "8910"]
url = "http://localhost:8910"
transport = "http"
`
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}

		entries, err := readMCPFromCodexConfigTOML(path)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if len(entries) != 2 {
			t.Fatalf("want 2 entries, got %d", len(entries))
		}

		// Map by name to make assertions order-independent (TOML
		// table iteration order is not guaranteed by the parser).
		byName := map[string]MCPServerEntry{}
		for _, e := range entries {
			byName[e.Name] = e
		}

		fs, ok := byName["fs"]
		if !ok {
			t.Fatalf("missing fs entry; got names: %v", entryNames(entries))
		}
		if fs.Command != "node" {
			t.Errorf("fs.command = %q, want node", fs.Command)
		}
		if len(fs.Args) != 1 || fs.Args[0] != "/opt/fs.js" {
			t.Errorf("fs.args = %v, want [/opt/fs.js]", fs.Args)
		}
		if fs.Env["TOKEN"] != "redacted" {
			t.Errorf("fs.env[TOKEN] = %q, want redacted", fs.Env["TOKEN"])
		}

		search, ok := byName["search"]
		if !ok {
			t.Fatalf("missing search entry")
		}
		if search.URL != "http://localhost:8910" {
			t.Errorf("search.url = %q", search.URL)
		}
		if search.Transport != "http" {
			t.Errorf("search.transport = %q", search.Transport)
		}
	})

	t.Run("missing_file_is_a_soft_failure", func(t *testing.T) {
		_, err := readMCPFromCodexConfigTOML(filepath.Join(t.TempDir(), "does-not-exist.toml"))
		if err == nil {
			t.Fatal("expected file-not-found error for the caller to soft-fall-back on")
		}
	})

	t.Run("missing_block_returns_empty", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.toml")
		body := `
# A real Codex config that doesn't register any MCP servers
[telemetry]
enabled = true
`
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		entries, err := readMCPFromCodexConfigTOML(path)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if len(entries) != 0 {
			t.Fatalf("want 0 entries when [mcp_servers] is absent, got %d", len(entries))
		}
	})

	t.Run("malformed_toml_returns_error", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.toml")
		if err := os.WriteFile(path, []byte("[mcp_servers.fs\ncommand = \"node\""), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readMCPFromCodexConfigTOML(path); err == nil {
			t.Fatal("expected TOML parse error for malformed file")
		}
	})
}

// TestReadMCPServersCodex_MergesGlobalAndProjectLocal verifies the
// integration-level read path: config.toml + .mcp.json are both
// consulted and de-duped by name.
func TestReadMCPServersCodex_MergesGlobalAndProjectLocal(t *testing.T) {
	homeDir := t.TempDir()
	cwdDir := t.TempDir()

	t.Setenv("HOME", homeDir)

	chdir(t, cwdDir)

	codexDir := filepath.Join(homeDir, ".codex")
	if err := os.MkdirAll(codexDir, 0o755); err != nil {
		t.Fatal(err)
	}
	tomlBody := `
[mcp_servers.global-fs]
command = "node"
args = ["/opt/global-fs.js"]
`
	if err := os.WriteFile(filepath.Join(codexDir, "config.toml"), []byte(tomlBody), 0o600); err != nil {
		t.Fatal(err)
	}

	dotmcp := []byte(`{
		"mcpServers": {
			"local-search": {"command": "search-mcp", "args": ["--port", "8910"]}
		}
	}`)
	if err := os.WriteFile(filepath.Join(cwdDir, ".mcp.json"), dotmcp, 0o600); err != nil {
		t.Fatal(err)
	}

	entries, err := readMCPServersCodex()
	if err != nil {
		t.Fatalf("readMCPServersCodex: %v", err)
	}

	got := entryNames(entries)
	sort.Strings(got)
	want := []string{"global-fs", "local-search"}
	if len(got) != len(want) {
		t.Fatalf("want %v, got %v", want, got)
	}
	for i, n := range want {
		if got[i] != n {
			t.Fatalf("want %v, got %v", want, got)
		}
	}
}

// TestReadMCPServersCodex_ProjectLocalOverridesGlobal is the
// regression for DeepSec finding "Codex project-local MCP overrides
// are shadowed by global entries". Before the fix, when both
// `~/.codex/config.toml` and `./.mcp.json` declared the same MCP
// server name, the global TOML entry was retained and the
// project-local definition was silently dropped -- inverting the
// precedence Codex itself uses at runtime. A malicious global
// `~/.codex/config.toml` (e.g. one written by a compromised tool or
// shared dotfiles repo) could therefore mask the project-local
// command/URL from DefenseClaw's inventory, watcher, snapshot, and
// admission paths even though Codex would actually invoke the
// project-local override. This test asserts that the project-local
// `command`/`args` win for a duplicate name.
func TestReadMCPServersCodex_ProjectLocalOverridesGlobal(t *testing.T) {
	homeDir := t.TempDir()
	cwdDir := t.TempDir()

	t.Setenv("HOME", homeDir)
	chdir(t, cwdDir)

	codexDir := filepath.Join(homeDir, ".codex")
	if err := os.MkdirAll(codexDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Global TOML registers an `fs` MCP server with the legitimate
	// IT-managed binary.
	tomlBody := `
[mcp_servers.fs]
command = "node"
args = ["/opt/IT/global-fs.js"]

[mcp_servers.fs.env]
TOKEN = "global-token"
`
	if err := os.WriteFile(filepath.Join(codexDir, "config.toml"), []byte(tomlBody), 0o600); err != nil {
		t.Fatal(err)
	}

	// Project-local .mcp.json re-declares `fs` with an attacker-
	// controlled path. Codex would actually invoke this one at
	// runtime, so DefenseClaw MUST scan and admit this one too.
	dotmcp := []byte(`{
		"mcpServers": {
			"fs": {"command": "node", "args": ["/repo/.attacker/fs.js"]}
		}
	}`)
	if err := os.WriteFile(filepath.Join(cwdDir, ".mcp.json"), dotmcp, 0o600); err != nil {
		t.Fatal(err)
	}

	entries, err := readMCPServersCodex()
	if err != nil {
		t.Fatalf("readMCPServersCodex: %v", err)
	}

	if len(entries) != 1 {
		t.Fatalf("want 1 deduped entry for `fs`, got %d (%v)", len(entries), entryNames(entries))
	}
	got := entries[0]
	if got.Name != "fs" {
		t.Fatalf("name = %q, want fs", got.Name)
	}
	if len(got.Args) != 1 || got.Args[0] != "/repo/.attacker/fs.js" {
		t.Errorf(
			"project-local override lost: args = %v, want [/repo/.attacker/fs.js] "+
				"(global entry has shadowed the local one again)",
			got.Args,
		)
	}
	if v, ok := got.Env["TOKEN"]; ok {
		t.Errorf(
			"project-local entry inherited global env (TOKEN=%q); precedence merge "+
				"should NOT splice fields across entries with the same name",
			v,
		)
	}
}

// TestReadMCPServersCodex_GlobalOnlyEntriesStillReadWhenLocalAbsent
// guards the merge behaviour when only one config is present: a
// global-only entry must still be visible to inventory/admission.
func TestReadMCPServersCodex_GlobalOnlyEntriesStillReadWhenLocalAbsent(t *testing.T) {
	homeDir := t.TempDir()
	cwdDir := t.TempDir()

	t.Setenv("HOME", homeDir)
	chdir(t, cwdDir)

	codexDir := filepath.Join(homeDir, ".codex")
	if err := os.MkdirAll(codexDir, 0o755); err != nil {
		t.Fatal(err)
	}
	tomlBody := `
[mcp_servers.global-only]
command = "node"
args = ["/opt/IT/global-only.js"]
`
	if err := os.WriteFile(filepath.Join(codexDir, "config.toml"), []byte(tomlBody), 0o600); err != nil {
		t.Fatal(err)
	}

	entries, err := readMCPServersCodex()
	if err != nil {
		t.Fatalf("readMCPServersCodex: %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "global-only" {
		t.Fatalf("want [global-only], got %v", entryNames(entries))
	}
}

func entryNames(es []MCPServerEntry) []string {
	out := make([]string, 0, len(es))
	for _, e := range es {
		out = append(out, e.Name)
	}
	return out
}

// chdir pushes the test's cwd into dir for the duration of the test
// and restores it via t.Cleanup. Wrapped here so each TOML test can
// isolate its `./.mcp.json` lookup without leaking state across
// tests in the package.
func chdir(t *testing.T, dir string) {
	t.Helper()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir %q: %v", dir, err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(prev)
	})
}
