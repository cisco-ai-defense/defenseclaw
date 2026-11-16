// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestShadowLanesGetTheOneStepVerdict is rel-1-0-10:GAP-1058. PATH-ETC-SHADOW's
// typed path check left the default and permissive catalogs for a pack_typed
// rule of the tool-shape table. In every tier the cd-first write gets the
// verdict of the one-step write, and the native Read and the MCP read of the
// file get one verdict: the MCP call is never judged harder than the native
// tool. The rows come from the cd-first targets (the shadow read row, and the
// sudoers row moved to the shadow file), so no new command text is typed here.
func TestShadowLanesGetTheOneStepVerdict(t *testing.T) {
	var read, sudoers cdFirstTarget
	for _, tg := range cdFirstTargets {
		switch tg.name {
		case "shadow read":
			read = tg
		case "sudoers":
			sudoers = tg
		}
	}
	if read.name == "" || sudoers.name == "" {
		t.Fatal("cd-first targets moved")
	}
	file := strings.TrimPrefix(read.one, "cat ")
	base := filepath.Base(file)
	writeOne := strings.ReplaceAll(sudoers.one, "sudoers", base)
	writeIn := strings.ReplaceAll(sudoers.inner, "sudoers", base)
	home := filepath.Join(t.TempDir(), "home", "alice")
	project := filepath.Join(home, "proj")
	if err := os.MkdirAll(filepath.Join(project, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	letter := map[string]string{"allow": "A", "alert": "L", "block": "B"}
	for _, p := range gap0437Packs {
		a := gap0437Server(t, p, "claudecode", "action")
		verdict := func(tool string, input map[string]any) string {
			out := gap0437Serve(t, a.handleAgentHook("claudecode"), "/api/v1/claude-code/hook", map[string]any{
				"hook_event_name": "PreToolUse", "session_id": "g1058-" + p.name, "cwd": project,
				"tool_name": tool, "tool_use_id": "tu-" + tool, "tool_input": input,
			})
			action, _ := out["action"].(string)
			return letter[action]
		}
		bash := func(command string) string { return verdict("Bash", map[string]any{"command": command}) }
		one := bash(writeOne)
		for _, command := range []string{"cd " + sudoers.dir + " && " + writeIn, "(cd " + sudoers.dir + "; " + writeIn + ")"} {
			if got := bash(command); got != one {
				t.Errorf("%s: %q is %s, the one-step form %q is %s", p.name, command, got, writeOne, one)
			}
		}
		if one == "A" {
			t.Errorf("%s: the one-step write %q is a clean allow", p.name, writeOne)
		}
		native := verdict("Read", map[string]any{"file_path": file})
		if mcp := verdict("mcp__filesystem__read_file", map[string]any{"path": file}); mcp != native {
			t.Errorf("%s: the MCP read of %s is %s, the native Read is %s", p.name, file, mcp, native)
		}
		if shell := bash(read.one); native == "A" && shell != "A" || native != "A" && shell == "A" {
			t.Errorf("%s: the native Read of %s is %s, %q is %s", p.name, file, native, read.one, shell)
		}
	}
}
