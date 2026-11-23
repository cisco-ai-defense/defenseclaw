// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package kit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// GAP-0643: the gateway decides a fetched MCP server (npx, uvx) with the
// folder facts the kit sends (GAP-0573). Two common ways to add one carried
// none: an argv-form "mcp add" (the Codex shell tool sends its command as a
// list) and a Write of an MCP config the connector does not load, which the
// gateway reads from the call itself. Both now send the folder record and
// what the folder offers a fetcher; nothing else changes.
func TestGAP0643KitSendsFetchFactsForArgvMCPAddAndUnloadedConfigWrite(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	t.Setenv("CODEX_HOME", filepath.Join(home, ".codex"))
	repo := filepath.Join(home, "work")
	if err := os.MkdirAll(filepath.Join(repo, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	const srv = "@modelcontextprotocol/server-filesystem"
	doc := `{"mcpServers":{"fs":{"command":"npx","args":["-y","` + srv + `","` + repo + `"]}}}`
	adds := []struct {
		name, connector, tool string
		input                 map[string]any
	}{
		{"codex shell bash -lc codex mcp add", "codex", "shell", map[string]any{"command": []any{"bash", "-lc", "codex mcp add fs -- npx -y " + srv + " " + repo}}},
		{"codex shell argv codex mcp add", "codex", "shell", map[string]any{"command": []any{"codex", "mcp", "add", "fs", "--", "npx", "-y", srv, repo}}},
		{"codex shell bash -lc claude mcp add", "codex", "shell", map[string]any{"command": []any{"bash", "-lc", "claude mcp add fs -- npx -y " + srv + " " + repo}}},
		{"claude code argv claude mcp add", "claudecode", "Bash", map[string]any{"command": []any{"claude", "mcp", "add", "fs", "--", "npx", "-y", srv, repo}}},
		{"claude code Bash string (unchanged)", "claudecode", "Bash", map[string]any{"command": "claude mcp add fs -- npx -y " + srv + " " + repo}},
		{"Write of an unloaded sub/.mcp.json", "claudecode", "Write", map[string]any{"file_path": filepath.Join(repo, "sub", ".mcp.json"), "content": doc}},
		{"Write of an unloaded relative sub/mcp.json", "codex", "Write", map[string]any{"filePath": "sub/mcp.json", "content": doc}},
	}
	collect := func(connector, tool string, input map[string]any) map[string]AttachedFile {
		t.Helper()
		payload, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": repo, "tool_name": tool, "tool_input": input})
		got := map[string]AttachedFile{}
		if f := CollectFacts(connector, "PreToolUse", payload, MaxAttachBytes); f != nil {
			for _, a := range f.Files {
				got[a.Role+" "+a.Path] = a
			}
		}
		return got
	}
	for _, c := range adds {
		if got := collect(c.connector, c.tool, c.input); len(got) == 0 {
			t.Errorf("%s: no files, want the folder record", c.name)
		} else if folder := map[string]string{"Write": filepath.Join(repo, "sub")}[c.tool]; folder == "" {
			if _, ok := got[roleFetchChecked+" "+repo]; !ok {
				t.Errorf("%s: files %v, want %s %s", c.name, keys(got), roleFetchChecked, repo)
			}
		} else if _, ok := got[roleFetchChecked+" "+folder]; !ok {
			// The config's folder, where the agent loads it (GAP-0646).
			t.Errorf("%s: files %v, want %s %s", c.name, keys(got), roleFetchChecked, folder)
		}
	}

	// The facts are the folder's: what resolves locally is reported, so the
	// gateway still counts the server as not known (GAP-0573 unchanged).
	write := func(p, s string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(repo, ".npmrc"), "node-options=--require ./x.js\n")
	write(filepath.Join(repo, "package.json"), `{"name":"p","bin":{"mcp-server-filesystem":"x.js"}}`)
	write(filepath.Join(repo, "node_modules", ".bin", "mcp-server-filesystem"), "#!/bin/sh\n")
	for _, c := range adds {
		got := collect(c.connector, c.tool, c.input)
		for _, want := range []string{
			roleFetchLocal + " " + filepath.Join(repo, ".npmrc"),
			roleFetchConfig + " " + filepath.Join(repo, "package.json"),
			roleFetchNames + " " + filepath.Join(repo, "node_modules"),
		} {
			if _, ok := got[want]; !ok {
				t.Errorf("%s: missing %q in %v", c.name, want, keys(got))
			}
		}
	}

	// Calls that add no server send no folder facts.
	for _, c := range []struct {
		name, tool string
		input      map[string]any
	}{
		{"argv ls", "shell", map[string]any{"command": []any{"ls", "-la"}}},
		{"Write of another file", "Write", map[string]any{"file_path": filepath.Join(repo, "sub", "notes.json"), "content": doc}},
		{"Read of an unloaded .mcp.json", "Read", map[string]any{"file_path": filepath.Join(repo, "sub", ".mcp.json")}},
		{"Edit of an unloaded .mcp.json", "Edit", map[string]any{"file_path": filepath.Join(repo, "sub", ".mcp.json"), "old_string": "a", "new_string": "b"}},
	} {
		if _, ok := collect("claudecode", c.tool, c.input)[roleFetchChecked+" "+repo]; ok {
			t.Errorf("%s: folder facts sent, want none", c.name)
		}
	}
}
