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

// GAP-0185 (E20): before a call of an MCP tool the kit attaches the
// repository's MCP config and its in-repository server files, and it turns
// the gateway's MCP refusal into the agent's closed deny.
func TestGAP0185MCPToolCallAttachesTheRepoConfig(t *testing.T) {
	cwd := t.TempDir()
	_ = os.WriteFile(filepath.Join(cwd, ".mcp.json"), []byte(`{"mcpServers":{"evil":{"command":"node","args":["srv.js"]}}}`), 0o644)
	_ = os.WriteFile(filepath.Join(cwd, "srv.js"), []byte("require('child_process')"), 0o644)
	payload, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "tool_name": "mcp__evil__run", "tool_input": map[string]any{}, "cwd": cwd})
	f := CollectFacts("claudecode", "PreToolUse", payload, MaxAttachBytes)
	roles := map[string]bool{}
	if f != nil {
		for _, a := range f.Files {
			roles[a.Role] = true
		}
	}
	if !roles["mcp_config"] || !roles["mcp_server"] {
		t.Fatalf("attached roles %v", roles)
	}
	// A non-MCP call attaches nothing.
	payload, _ = json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": map[string]any{"command": "ls"}, "cwd": cwd})
	if f := CollectFacts("claudecode", "PreToolUse", payload, MaxAttachBytes); f != nil && len(f.Files) != 0 {
		t.Fatalf("Bash attached %d files", len(f.Files))
	}
}

// GAP-0176 in the kit: the server files are chosen by the exact keys the
// agent reads, so a case variant cannot hide the real command's files.
func TestGAP0176KitReadsTheExactMCPKeys(t *testing.T) {
	p := filepath.Join(t.TempDir(), ".mcp.json")
	_ = os.WriteFile(p, []byte(`{"mcpServers":{"x":{"command":"node","args":["srv.js"],"Command":"true","ARGS":[]}}}`), 0o644)
	got := claudeMCPServers(p)
	if len(got) != 1 || got[0].Command != "node" || len(got[0].Args) != 1 || got[0].Args[0] != "srv.js" {
		t.Fatalf("servers %+v", got)
	}
}

func TestGAP0185MCPRefusalIsAClosedDeny(t *testing.T) {
	answer, _ := json.Marshal(map[string]string{"reason": MCPRefusedCode, "message": "DefenseClaw refused the MCP server evil: fetch-and-exec"})
	msg, ok := signinRefusal(403, answer)
	if !ok || msg == "" {
		t.Fatalf("refusal not recognised: %q %v", msg, ok)
	}
	if _, ok := signinRefusal(403, []byte(`{"reason":"something_else"}`)); ok {
		t.Fatal("an unknown reason was taken as a refusal")
	}
}

// GAP-0039/0164: a Read of a file in a skill root runs the folder pass in
// that call (one rule for every skill, by content digest), plugin skills
// included; a Read elsewhere does not.
func TestGAP0039SkillReadRunsTheFolderPass(t *testing.T) {
	home := t.TempDir()
	for _, p := range []string{filepath.Join(home, ".claude", "skills", "x", "SKILL.md"), filepath.Join(home, ".claude", "plugins", "cache", "m", "p", "1", "skills", "y", "SKILL.md")} {
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		_ = os.WriteFile(p, []byte("---\nname: x\n---\n"), 0o644)
		payload, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": map[string]any{"file_path": p}, "cwd": home})
		f := CollectFacts("claudecode", "PreToolUse", payload, MaxAttachBytes)
		if f == nil || !f.readsSkill || len(f.Files) != 0 {
			t.Fatalf("%s: facts %+v", p, f)
		}
	}
	other := filepath.Join(home, "README.md")
	_ = os.WriteFile(other, []byte("hi"), 0o644)
	payload, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": map[string]any{"file_path": other}, "cwd": home})
	if f := CollectFacts("claudecode", "PreToolUse", payload, MaxAttachBytes); f != nil && f.readsSkill {
		t.Fatal("a Read outside the skill roots runs the folder pass")
	}
}
