// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// This test writes Linux hook paths (/work/sub/.mcp.json); Agent Substrate pods are Linux, and those paths are not absolute on Windows hosts.
//go:build !windows

package attest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// GAP-0646: a whole Write of an MCP config the connector does not load
// (/work/sub/.mcp.json from /work) is checked for what its fetcher resolves
// in the config's folder, where the agent loads it: a program of
// /work/sub/node_modules/.bin that stands in for the fetched package makes
// the server the folder's, not folder-clean. A config at the top of cwd, a
// config folder (.cursor) and a home config keep cwd.
func TestGAP0646NestedMCPConfigWriteIsCheckedInItsFolder(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	repo := filepath.Join(home, "work")
	bin := filepath.Join(repo, "sub", "node_modules", ".bin", "mcp-server-filesystem")
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	doc := `{"mcpServers":{"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","` + repo + `"]}}}`
	payload, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": repo, "tool_name": "Write",
		"tool_input": map[string]any{"file_path": filepath.Join(repo, "sub", ".mcp.json"), "content": doc}})
	facts := kit.CollectFacts("claudecode", "PreToolUse", payload, kit.MaxAttachBytes)
	if facts == nil {
		t.Fatal("no kit facts for the write")
	}
	var files []AttachedFile
	raw, _ := json.Marshal(facts.Files)
	if err := json.Unmarshal(raw, &files); err != nil {
		t.Fatal(err)
	}
	assets := HookAssets(payload, files)
	if len(assets) != 1 || assets[0].Server == nil {
		t.Fatalf("assets %+v, want the fs server", assets)
	}
	if want := filepath.Join(repo, "sub"); assets[0].Project != filepath.ToSlash(want) {
		t.Errorf("project %q, want the config folder %q", assets[0].Project, want)
	}
	if runsNothingOfFolder(*assets[0].Server, assets[0].Project, files) {
		t.Errorf("the server reads as folder-clean with %s in the config folder", bin)
	}

	for _, c := range []struct{ target, cwd, want string }{
		{"/work/sub/.mcp.json", "/work", "/work/sub"},
		{"/work/.mcp.json", "/work", "/work"},
		{"/work/.cursor/mcp.json", "/work", "/work"},
		{"/work/sub/.cursor/mcp.json", "/work", "/work/sub"},
		{"/home/u/.claude.json", "/work", "/work"},
		{"/home/u/.codex/config.toml", "/work", "/work"},
		{"/other/.mcp.json", "/work", "/work"},
	} {
		if got := kit.MCPConfigProject(c.target, c.cwd); got != c.want {
			t.Errorf("MCPConfigProject(%q, %q) = %q, want %q", c.target, c.cwd, got, c.want)
		}
	}
}
