// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The actor kit runs in Linux actor images only (kit.Config refuses other systems); its tests render and
// resolve paths for Linux.
//go:build linux

package kit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFactsResolveLinksAndAttachReadTargets(t *testing.T) {
	repo := t.TempDir()
	outside := t.TempDir()
	secret := filepath.Join(outside, "id_rsa")
	os.WriteFile(secret, []byte("KEY"), 0o600)
	os.Symlink(secret, filepath.Join(repo, "notes.txt"))
	skill := filepath.Join(repo, ".claude", "skills", "s1")
	os.MkdirAll(skill, 0o755)
	os.WriteFile(filepath.Join(skill, "big.txt"), []byte(strings.Repeat("x", 100)), 0o644)

	payload, _ := json.Marshal(map[string]any{
		"hook_event_name": "PreToolUse", "cwd": repo, "tool_name": "Read",
		"tool_input": map[string]any{"file_path": "notes.txt"},
	})
	f := CollectFacts("claudecode", "", payload, 1<<20)
	if f == nil || len(f.Paths) != 1 {
		t.Fatalf("facts %+v", f)
	}
	p := f.Paths[0]
	wantResolved, _ := filepath.EvalSymlinks(secret)
	if p.Field != "tool_input.file_path" || p.Abs != filepath.Join(repo, "notes.txt") || p.Resolved != wantResolved ||
		p.InsideCWD || len(p.LinkChain) != 1 || p.Type != "file" {
		t.Fatalf("path fact %+v", p)
	}
	// An ordinary read target's content has no reader at the gateway
	// (GAP-0072): only its path facts go.
	if len(f.Files) != 0 {
		t.Fatalf("files %+v", f.Files)
	}

	payload, _ = json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": repo, "tool_name": "Read",
		"tool_input": map[string]any{"file_path": filepath.Join(skill, "big.txt")}})
	f = CollectFacts("claudecode", "", payload, 10)
	if !f.Truncated || len(f.Files) != 1 || len(f.Files[0].Content) != 10 || !f.Files[0].Truncated || f.Files[0].Size != 100 {
		t.Fatalf("capped %+v", f)
	}
	// A write does not attach content.
	payload, _ = json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": repo, "tool_name": "Write",
		"tool_input": map[string]any{"file_path": "new.txt", "content": "x"}})
	f = CollectFacts("claudecode", "", payload, 1<<20)
	if len(f.Files) != 0 || f.Paths[0].Type != "missing" || !f.Paths[0].InsideCWD {
		t.Fatalf("write facts %+v", f)
	}
}

func TestFactsApplyPatchPaths(t *testing.T) {
	repo := t.TempDir()
	patch := "*** Begin Patch\n*** Update File: a.go\n@@\n-x\n+y\n*** Add File: ../../etc/cron.d/x\n+* * * * * root sh\n*** End Patch\n"
	payload, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": repo, "tool_name": "apply_patch",
		"tool_input": map[string]any{"command": []any{"apply_patch", patch}}})
	f := CollectFacts("codex", "PreToolUse", payload, 1<<20)
	if f == nil || len(f.Paths) != 2 || !f.Paths[0].InsideCWD || f.Paths[1].InsideCWD {
		t.Fatalf("patch facts %+v", f)
	}
}

func TestFactsMCPAdmission(t *testing.T) {
	repo := t.TempDir()
	os.MkdirAll(filepath.Join(repo, "tools"), 0o755)
	os.WriteFile(filepath.Join(repo, "tools", "srv.py"), []byte("print('mcp')"), 0o644)
	os.WriteFile(filepath.Join(repo, ".mcp.json"), []byte(`{"mcpServers":{"local":{"command":"python3","args":["tools/srv.py"]},"sys":{"command":"/usr/bin/env","args":["node"]},"web":{"type":"http","url":"https://x"}}}`), 0o644)
	payload, _ := json.Marshal(map[string]any{"hook_event_name": "SessionStart", "cwd": repo})
	f := CollectFacts("claudecode", "", payload, 1<<20)
	if f == nil || len(f.Files) != 2 || f.Files[0].Role != "mcp_config" || f.Files[1].Role != "mcp_server" ||
		string(f.Files[1].Content) != "print('mcp')" {
		t.Fatalf("mcp facts %+v", f)
	}
	os.MkdirAll(filepath.Join(repo, ".codex"), 0o755)
	os.WriteFile(filepath.Join(repo, ".codex", "config.toml"), []byte("[mcp_servers.local]\ncommand = \"./tools/srv.py\"\n"), 0o644)
	f = CollectFacts("codex", "SessionStart", payload, 1<<20)
	if f == nil || len(f.Files) != 2 || f.Files[1].Path != filepath.Join(repo, "tools", "srv.py") {
		t.Fatalf("codex mcp facts %+v", f)
	}
}
