// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/assetfacts"
)

// GAP-0570, GAP-0576: the standalone hook reports, read as the user, the
// name an invoked skill folder declares and the MCP server a tool call names.
func TestHookAssetFactsReportWhatTheGatewayCannotRead(t *testing.T) {
	home := t.TempDir()
	for _, name := range []string{"HOME", "USERPROFILE"} {
		t.Setenv(name, home)
	}
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	skill := filepath.Join(home, ".claude", "skills", "epa-alias")
	if err := os.MkdirAll(skill, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skill, "SKILL.md"), []byte("---\nname: epa-deny\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	facts, ok := assetfacts.Decode(hookAssetFacts("claudecode", []byte(`{"tool_name":"Skill","tool_input":{"skill":"epa-alias"}}`)))
	if !ok || len(facts.Skills) != 1 || facts.Skills[0].Folder != "epa-alias" || facts.Skills[0].Declared != "epa-deny" {
		t.Fatalf("skill facts = %+v (ok=%v)", facts, ok)
	}

	state := `{"mcpServers":{"notes":{"type":"http","url":"http://127.0.0.1:28561/mcp"}}}`
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(state), 0o600); err != nil {
		t.Fatal(err)
	}
	facts, ok = assetfacts.Decode(hookAssetFacts("claudecode", []byte(`{"tool_name":"mcp__notes__count_words","cwd":"`+filepath.ToSlash(home)+`"}`)))
	if !ok || facts.MCP == nil || facts.MCP.Name != "notes" || facts.MCP.URL != "http://127.0.0.1:28561/mcp" {
		t.Fatalf("mcp facts = %+v (ok=%v)", facts, ok)
	}
}

// GAP-0954: an agent started with an MCP config on its command line uses the
// server that config defines, not the one its files name under the same
// name: claude --strict-mcp-config --mcp-config FILE and codex -c
// mcp_servers.<name>.url. A command-line source the hook cannot read leaves
// the server unproven.
func TestHookAssetFactsReadTheAgentCommandLine(t *testing.T) {
	home := t.TempDir()
	for _, name := range []string{"HOME", "USERPROFILE"} {
		t.Setenv(name, home)
	}
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	t.Setenv("CODEX_HOME", "")
	write := func(path, data string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(home, ".claude.json"), `{"mcpServers":{"acme-notes":{"type":"http","url":"http://127.0.0.1:28581/mcp"}}}`)
	write(filepath.Join(home, ".codex", "config.toml"), "[mcp_servers.acme-notes]\nurl = \"http://127.0.0.1:28581/mcp\"\n")
	write(filepath.Join(home, "x.json"), `{"mcpServers":{"acme-notes":{"type":"http","url":"http://127.0.0.1:28583/mcp"}}}`)
	var args []string
	saved := hookAgentCommandLine
	t.Cleanup(func() { hookAgentCommandLine = saved })
	hookAgentCommandLine = func() ([]string, string, error) { return args, home, nil }
	facts := func(connector, tool string) assetfacts.Facts {
		t.Helper()
		got, _ := assetfacts.Decode(hookAssetFacts(connector, []byte(`{"tool_name":"`+tool+`","cwd":"`+filepath.ToSlash(home)+`"}`)))
		return got
	}
	want := "http://127.0.0.1:28583/mcp"
	args = []string{"claude", "--strict-mcp-config", "--mcp-config", "x.json"}
	if got := facts("claudecode", "mcp__acme-notes__count_words"); got.MCP == nil || got.MCP.URL != want || got.MCP.Source != assetfacts.SourceCommandLine {
		t.Fatalf("claude --mcp-config facts = %+v, want the command-line definition", got)
	}
	args = []string{"codex", "-c", `mcp_servers.acme-notes.url="` + want + `"`}
	if got := facts("codex", "mcp__acme_notes__count_words"); got.MCP == nil || got.MCP.Name != "acme-notes" || got.MCP.URL != want || got.MCP.Source != assetfacts.SourceCommandLine {
		t.Fatalf("codex -c facts = %+v, want the command-line definition", got)
	}
	args = []string{"claude", "--mcp-config", filepath.Join(home, "missing.json")}
	if got := facts("claudecode", "mcp__acme-notes__count_words"); got.MCP != nil || got.MCPUnproven != "acme-notes" {
		t.Fatalf("unreadable --mcp-config facts = %+v, want the server unproven", got)
	}
}
