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
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/agentprocess"
	"github.com/defenseclaw/defenseclaw/internal/assetfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
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
	// GAP-0968: a skill typed as /name reports its folder too.
	facts, _ = assetfacts.Decode(hookAssetFacts("claudecode", []byte(`{"prompt":"/epa-alias go"}`)))
	if len(facts.SkillDirs) != 1 || facts.SkillDirs[0] != skill {
		t.Fatalf("slash skill dirs = %+v, want %s", facts.SkillDirs, skill)
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

func TestGAP0535HookReportsDeclaredNameAfterDirectoryChange(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	dir := filepath.Join(home, ".claude", "skills", "folder")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: listed-name\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	input, err := json.Marshal(map[string]any{
		"tool_name": "Bash", "cwd": t.TempDir(),
		"tool_input": map[string]any{"command": "cd " + filepath.Join(home, ".claude") + " && cat skills/folder/SKILL.md"},
	})
	if err != nil {
		t.Fatal(err)
	}
	facts, ok := assetfacts.Decode(hookAssetFacts("claudecode", input))
	if !ok || len(facts.DeclaredFor("folder")) != 1 || facts.DeclaredFor("folder")[0] != "listed-name" {
		t.Fatalf("declared skill facts = %+v (ok=%v)", facts, ok)
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

// GAP-0686: the hook says when the definition it read is in the config.toml
// of a CODEX_HOME other than ~/.codex, so the gateway judges the file the
// agent runs and a managed Windows gateway admits only a published one.
func TestHookAssetFactsMarkTheRelocatedCodexConfig(t *testing.T) {
	home := t.TempDir()
	for _, name := range []string{"HOME", "USERPROFILE"} {
		t.Setenv(name, home)
	}
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	saved := hookAgentCommandLine
	t.Cleanup(func() { hookAgentCommandLine = saved })
	hookAgentCommandLine = func() ([]string, string, error) { return nil, "", agentprocess.ErrNoAgent }
	stubHookAgentWorkingDirectory(t, "")
	write := func(dir, url string) {
		t.Helper()
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte("[mcp_servers.notes]\nurl = \""+url+"\"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(home, ".codex"), "http://127.0.0.1:28562/mcp")
	relocated := filepath.Join(t.TempDir(), "codex-home")
	write(relocated, "http://127.0.0.1:28561/mcp")
	project := t.TempDir()
	facts := func(connector string) *assetfacts.MCPServer {
		t.Helper()
		got, _ := assetfacts.Decode(hookAssetFacts(connector, []byte(`{"tool_name":"mcp__notes__count_words","cwd":"`+filepath.ToSlash(project)+`"}`)))
		return got.MCP
	}
	t.Setenv("CODEX_HOME", relocated)
	if got := facts("codex"); got == nil || got.URL != "http://127.0.0.1:28561/mcp" || !got.Relocated {
		t.Fatalf("CODEX_HOME facts = %+v, want the relocated definition marked", got)
	}
	// Twins that stay unmarked: no CODEX_HOME, CODEX_HOME naming the default
	// folder, and another connector.
	t.Setenv("CODEX_HOME", "")
	if got := facts("codex"); got == nil || got.URL != "http://127.0.0.1:28562/mcp" || got.Relocated {
		t.Fatalf("default facts = %+v, want the default definition unmarked", got)
	}
	t.Setenv("CODEX_HOME", filepath.Join(home, ".codex"))
	if got := facts("codex"); got == nil || got.Relocated {
		t.Fatalf("CODEX_HOME=~/.codex facts = %+v, want it unmarked", got)
	}
	// The digest binds the claim to the complete definition.
	t.Setenv("CODEX_HOME", relocated)
	if got := facts("codex"); got == nil || got.Digest != config.MCPLaunchDigest(config.MCPServerEntry{URL: "http://127.0.0.1:28561/mcp"}) || got.Digest == "" {
		t.Fatalf("CODEX_HOME facts = %+v, want the digest of the definition", got)
	}
	// A project .codex/config.toml takes precedence over the user config and
	// is marked as a source the enumerator does not publish.
	write(filepath.Join(project, ".codex"), "http://127.0.0.1:28563/mcp")
	// Codex runs a project definition only for a project its user config
	// trusts: until then the user definition is the one in effect and nothing
	// is marked as an unpublished source (GAP-0686 review 4).
	if got := facts("codex"); got == nil || got.URL != "http://127.0.0.1:28561/mcp" || !got.Relocated || got.ProjectScope {
		t.Fatalf("untrusted project facts = %+v, want the user definition, not the project one", got)
	}
	trust, err := os.OpenFile(filepath.Join(relocated, "config.toml"), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trust.WriteString("\n[projects." + strconv.Quote(project) + "]\ntrust_level = \"trusted\"\n"); err != nil {
		t.Fatal(err)
	}
	if err := trust.Close(); err != nil {
		t.Fatal(err)
	}
	if got := facts("codex"); got == nil || got.URL != "http://127.0.0.1:28563/mcp" || got.Relocated || !got.ProjectScope || got.Digest == "" {
		t.Fatalf("project facts = %+v, want the project definition marked", got)
	}
	if err := os.RemoveAll(filepath.Join(project, ".codex")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CODEX_HOME", relocated)
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{"mcpServers":{"notes":{"type":"http","url":"http://127.0.0.1:28562/mcp"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := facts("claudecode"); got == nil || got.Relocated {
		t.Fatalf("claude facts = %+v, want them unmarked", got)
	}
}

// GAP-0699, GAP-0701: the hook reads, as the user, the text of the skill
// folder a request selects and of the plugin it belongs to, for a gateway
// that may not read the profile; a request that selects neither reads none.
func TestHookAssetFactsCarryTheTextOfTheSelectedSkillAndPlugin(t *testing.T) {
	home := t.TempDir()
	for _, name := range []string{"HOME", "USERPROFILE"} {
		t.Setenv(name, home)
	}
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	saved := hookAgentCommandLine
	t.Cleanup(func() { hookAgentCommandLine = saved })
	hookAgentCommandLine = func() ([]string, string, error) { return nil, "", agentprocess.ErrNoAgent }
	stubHookAgentWorkingDirectory(t, "")
	write := func(path, text string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(home, ".claude", "skills", "np10", "SKILL.md"), "# np10\nskill text\n")
	plugin := filepath.Join(t.TempDir(), "r109kit")
	write(filepath.Join(plugin, "skills", "notes", "SKILL.md"), "# notes\nplugin skill text\n")
	registry, err := json.Marshal(map[string]any{"plugins": map[string]any{"r109kit@r109mkt": []map[string]string{{"installPath": plugin}}}})
	if err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(home, ".claude", "plugins", "installed_plugins.json"), string(registry))
	project := t.TempDir()
	facts := func(payload string) assetfacts.Facts {
		t.Helper()
		got, _ := assetfacts.Decode(hookAssetFacts("claudecode", []byte(payload)))
		return got
	}
	cwd := filepath.ToSlash(project)
	got := facts(`{"tool_name":"Skill","tool_input":{"skill":"np10"},"cwd":"` + cwd + `"}`)
	if c := got.ContentsFor(assetfacts.ContentSkill, "np10"); len(c) != 1 || len(c[0].Files) != 1 || c[0].Files[0].Rel != "SKILL.md" || c[0].Files[0].Text != "# np10\nskill text\n" {
		t.Fatalf("skill facts = %+v, want the SKILL.md text", got)
	}
	for _, payload := range []string{
		`{"hook_event_name":"UserPromptExpansion","prompt":"/r109kit:notes","command_name":"r109kit:notes","cwd":"` + cwd + `"}`,
		`{"tool_name":"mcp__plugin_r109kit_kit-time__kit_time","tool_input":{},"cwd":"` + cwd + `"}`,
		`{"tool_name":"Skill","tool_input":{"skill":"r109kit:notes"},"cwd":"` + cwd + `"}`,
	} {
		if c := facts(payload).ContentsFor(assetfacts.ContentPlugin, "r109kit"); len(c) != 1 || len(c[0].Files) != 1 || c[0].Files[0].Rel != "skills/notes/SKILL.md" {
			t.Fatalf("plugin facts for %s = %+v, want the plugin text", payload, c)
		}
	}
	for _, payload := range []string{
		`{"tool_name":"Bash","tool_input":{"command":"ls"},"cwd":"` + cwd + `"}`,
		`{"tool_name":"Skill","tool_input":{"skill":"missing"},"cwd":"` + cwd + `"}`,
	} {
		if got := facts(payload); len(got.Contents) != 0 {
			t.Fatalf("facts for %s = %+v, want no text read", payload, got)
		}
	}
}
