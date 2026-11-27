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

func TestFactsResolveLinksAndReadsOfSkills(t *testing.T) {
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
	// A read of a skill's file runs the skill folder pass in that call (the
	// folder's digest decides, GAP-0039/0164); the read target itself is
	// not attached (its role had no reader at the gateway, GAP-0185).
	f = CollectFacts("claudecode", "", payload, 10)
	if f == nil || !f.readsSkill || len(f.Files) != 0 {
		t.Fatalf("skill read %+v", f)
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
	// The connector reads user-scope configs too (GAP-0185): an empty home.
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	t.Setenv("CODEX_HOME", "")
	repo := t.TempDir()
	os.MkdirAll(filepath.Join(repo, "tools"), 0o755)
	os.WriteFile(filepath.Join(repo, "tools", "srv.py"), []byte("print('mcp')"), 0o644)
	os.WriteFile(filepath.Join(repo, ".mcp.json"), []byte(`{"mcpServers":{"local":{"command":"python3","args":["tools/srv.py"]},"sys":{"command":"/usr/bin/env","args":["node"]},"web":{"type":"http","url":"https://x"}}}`), 0o644)
	payload, _ := json.Marshal(map[string]any{"hook_event_name": "SessionStart", "cwd": repo})
	f := CollectFacts("claudecode", "", payload, 1<<20)
	f = withoutFolderFacts(f)
	if f == nil || len(f.Files) != 2 || f.Files[0].Role != "mcp_config" || f.Files[1].Role != "mcp_server" ||
		string(f.Files[1].Content) != "print('mcp')" {
		t.Fatalf("mcp facts %+v", f)
	}
	os.MkdirAll(filepath.Join(repo, ".codex"), 0o755)
	os.WriteFile(filepath.Join(repo, ".codex", "config.toml"), []byte("[mcp_servers.local]\ncommand = \"./tools/srv.py\"\n"), 0o644)
	f = CollectFacts("codex", "SessionStart", payload, 1<<20)
	f = withoutFolderFacts(f)
	if f == nil || len(f.Files) != 2 || f.Files[1].Path != filepath.Join(repo, "tools", "srv.py") {
		t.Fatalf("codex mcp facts %+v", f)
	}
}

// withoutFolderFacts drops the folder facts the kit reports for registry
// fetchers and bare commands (GAP-0573, GAP-0575), which these rows do not
// look at.
func withoutFolderFacts(f *Facts) *Facts {
	if f == nil {
		return nil
	}
	var keep []AttachedFile
	for _, a := range f.Files {
		switch a.Role {
		case roleFetchChecked, roleFetchLocal, roleFetchConfig, roleFetchNames, roleFetchBins, roleCommandPath, roleCommandPathHit:
		default:
			keep = append(keep, a)
		}
	}
	f.Files = keep
	return f
}

// GAP-0577: the gateway needs exact pre-edit bytes, not invented JSON
// contexts. Attach only settings edits, and stop at the local read budget.
func TestFactsAgentHookBefore(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "settings.json")
	before := []byte(`{"model":"z\u007az","hooks":{}}`)
	if err := os.WriteFile(target, before, 0600); err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"Edit", "MultiEdit", "Read", "Write", "str_replace", "multi_edit", "write_file"} {
		payload, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": home, "tool_name": tool,
			"tool_input": map[string]any{"file_path": "~/.claude/settings.json", "old_string": "007a", "new_string": "0079"}})
		for _, cap := range []int64{0, int64(len(before) - 1), int64(len(before)), 1 << 20} {
			facts := CollectFacts("claudecode", "", payload, cap)
			var files []AttachedFile
			for _, f := range facts.Files {
				if f.Role == "agent_hook_config_before" {
					files = append(files, f)
				}
			}
			if tool == "Read" {
				if len(files) != 0 {
					t.Fatalf("%s attached pre-edit content", tool)
				}
				continue
			}
			if len(files) != 1 || files[0].Path != target {
				t.Fatalf("%s facts %+v", tool, files)
			}
			f := files[0]
			if cap < int64(len(before)) {
				if !f.Truncated || len(f.Content) != 0 {
					t.Fatal("over-budget file was attached")
				}
			} else if f.Truncated || string(f.Content) != string(before) || f.SHA256 == "" {
				t.Fatalf("lost exact pre-edit bytes: %+v", f)
			}
		}
	}
	if err := os.WriteFile(target, []byte(strings.Repeat("x", 65537)), 0600); err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": home, "tool_name": "Edit", "tool_input": map[string]any{"file_path": target}})
	facts := CollectFacts("claudecode", "", payload, 1<<20)
	if len(facts.Files) != 1 || !facts.Files[0].Truncated || len(facts.Files[0].Content) != 0 {
		t.Fatal("settings read exceeded the fixed local cap")
	}
}

// Missing and invalid JSON are exact observations, unlike a failed bounded read.
func TestFactsAgentHookBeforeMissingAndInvalid(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	target := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{"missing", "", "{broken"} {
		if body != "missing" {
			if err := os.WriteFile(target, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
		}
		payload, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "tool_name": "Edit", "tool_input": map[string]any{"file_path": target}})
		facts := CollectFacts("claudecode", "", payload, 1<<20)
		if facts == nil || len(facts.Files) != 1 {
			t.Fatalf("%s: %+v", body, facts)
		}
		f := facts.Files[0]
		if f.Truncated || f.SHA256 == "" {
			t.Fatalf("%s: not an exact before-state: %+v", body, f)
		}
	}
}

func TestFactsAgentHookBeforeAliases(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"settings.json", "settings.local.json"} {
		target := filepath.Join(dir, name)
		if err := os.WriteFile(target, []byte("{broken"), 0600); err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"file_path", "filePath", "path"} {
			for _, tool := range []string{"Edit", "MultiEdit", "edit_file", "str_replace", "multi_edit", "multi-edit", "Write", "write_file", "writefile", "write-file", "create", "create_file"} {
				payload, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": home, "tool_name": tool, "tool_input": map[string]any{key: target}})
				facts := CollectFacts("claudecode", "", payload, 1<<20)
				if facts == nil || len(facts.Files) != 1 || facts.Files[0].Truncated || string(facts.Files[0].Content) != "{broken" {
					t.Fatalf("%s %s %s lost before-state: %+v", name, key, tool, facts)
				}
			}
		}
	}
}

func TestFactsAgentHookBeforePatchTargets(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(dir, "settings.json")
	second := filepath.Join(dir, "settings.local.json")
	for _, target := range []string{first, second} {
		if err := os.WriteFile(target, []byte("{}"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	patch := "*** Begin Patch\n*** Update File: " + first + "\n@@\n-{}\n+{}\n*** Update File: " + second + "\n@@\n-{}\n+{}\n*** End Patch\n"
	for _, tool := range []string{"apply_patch", "applypatch", "apply-patch", "patch"} {
		for _, budget := range []int64{2, 4} {
			payload, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": home, "tool_name": tool,
				"tool_input": map[string]any{"input": patch, "patch": patch}})
			facts := CollectFacts("claudecode", "", payload, budget)
			if facts == nil || len(facts.Files) != 2 {
				t.Fatalf("%s: lost or duplicate patch targets: %+v", tool, facts)
			}
			total := 0
			for _, f := range facts.Files {
				total += len(f.Content)
			}
			if int64(total) != budget {
				t.Fatalf("%s: bytes=%d budget=%d", tool, total, budget)
			}
			if facts.Files[0].Truncated || facts.Files[1].Truncated != (budget == 2) {
				t.Fatalf("%s: shared patch budget lost: %+v", tool, facts.Files)
			}
		}
	}
}
