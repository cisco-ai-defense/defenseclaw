// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package kit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-0573: the kit reports what the folder and its parents offer a
// registry fetcher, so the gateway can tell a registry package from one
// npx would run out of the project (its bin, node_modules/.bin, .npmrc).
func TestGAP0573KitReportsFetcherFolderFacts(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	outer := filepath.Join(home, "work")
	repo := filepath.Join(outer, "repo", "sub")
	write := func(p, s string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(repo, ".mcp.json"), `{"mcpServers":{"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/tmp"]},"bare":{"command":"gap0573-kit-srv"}}}`)
	write(filepath.Join(repo, ".npmrc"), "node-options=--require ./x.js\n")
	write(filepath.Join(repo, "package.json"), `{"name":"p","bin":{"x":"x.js"}}`)
	write(filepath.Join(repo, "node_modules", ".bin", "mcp-server-filesystem"), "#!/bin/sh\n")
	write(filepath.Join(repo, "node_modules", "@modelcontextprotocol", "server-filesystem", "package.json"), "{}")
	write(filepath.Join(outer, "uv.toml"), "")           // a parent of the folder
	write(filepath.Join(home, ".npmrc"), "registry=x\n") // the home folder: not the project's
	bin := t.TempDir()
	write(filepath.Join(bin, "gap0573-kit-srv"), "#!/bin/sh\n")
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	payload, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": repo, "tool_name": "mcp__fs__read", "tool_input": map[string]any{}})
	f := CollectFacts("claudecode", "PreToolUse", payload, MaxAttachBytes)
	if f == nil {
		t.Fatal("no facts")
	}
	got := map[string]AttachedFile{}
	for _, a := range f.Files {
		got[a.Role+" "+a.Path] = a
	}
	for _, want := range []string{
		roleFetchChecked + " " + repo,
		roleFetchLocal + " " + filepath.Join(repo, ".npmrc"),
		roleFetchConfig + " " + filepath.Join(repo, "package.json"),
		roleFetchNames + " " + filepath.Join(repo, "node_modules"),
		roleFetchLocal + " " + filepath.Join(outer, "uv.toml"),
		roleCommandPath + " gap0573-kit-srv",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %q in %v", want, keys(got))
		}
	}
	if _, ok := got[roleFetchLocal+" "+filepath.Join(home, ".npmrc")]; ok {
		t.Error("the home folder's .npmrc was reported as the project's")
	}
	n := got[roleFetchNames+" "+filepath.Join(repo, "node_modules")]
	if s := string(n.Content); !strings.Contains(s, ".bin/mcp-server-filesystem") || !strings.Contains(s, "@modelcontextprotocol/server-filesystem") || n.Truncated {
		t.Errorf("node_modules names = %q (truncated %v)", s, n.Truncated)
	}
	if c := got[roleCommandPath+" gap0573-kit-srv"]; string(c.Content) != filepath.Join(bin, "gap0573-kit-srv") {
		t.Errorf("command path = %q", c.Content)
	}
	if pj := got[roleFetchConfig+" "+filepath.Join(repo, "package.json")]; !strings.Contains(string(pj.Content), `"bin"`) {
		t.Errorf("package.json content = %q", pj.Content)
	}

	// A command that adds a server reports the folder too (the server is
	// decided in that call).
	payload, _ = json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": repo, "tool_name": "Bash",
		"tool_input": map[string]any{"command": "claude mcp add fs -- npx -y some-mcp"}})
	f = CollectFacts("claudecode", "PreToolUse", payload, MaxAttachBytes)
	if f == nil || len(f.Files) == 0 || f.Files[0].Role != roleFetchChecked {
		t.Fatalf("mcp add: facts %+v, want the folder record", f)
	}
	// Any other command reports nothing new.
	payload, _ = json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": repo, "tool_name": "Bash",
		"tool_input": map[string]any{"command": "ls"}})
	if f = CollectFacts("claudecode", "PreToolUse", payload, MaxAttachBytes); f != nil && len(f.Files) > 0 {
		t.Errorf("ls: files %+v, want none", f.Files)
	}
}

func keys(m map[string]AttachedFile) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
