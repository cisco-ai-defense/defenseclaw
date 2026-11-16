// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// shadowLaneVerdict is one hook verdict as action letter and severity letter
// (AM: allow MEDIUM, B: block, A: allow with no finding).
func shadowLaneVerdict(out map[string]any) string {
	letter := map[string]string{"allow": "A", "alert": "L", "block": "B"}
	action, _ := out["action"].(string)
	severity, _ := out["severity"].(string)
	if severity == "" || severity == "NONE" {
		return letter[action]
	}
	return letter[action] + severity[:1]
}

// TestShadowLanesGetTheOneStepVerdict is rel-1-0-10:GAP-1058 and GAP-1069.
// PATH-ETC-SHADOW's typed path check left the default and permissive catalogs
// for a pack_typed rule of the tool-shape table. Through the Claude Code hook
// in the five tiers: the one-step spellings keep rel's verdict (the
// security-suite read and targeted account lookup rows, and the read verbs of
// the s7-g1058rev rows), every cd-first spelling gets the one-step verdict,
// the native Read and the MCP read of the file get one verdict, and a write of
// the file after a cd is never a clean allow. The commands come from the
// corpus and the cd-first targets, transformed in code.
func TestShadowLanesGetTheOneStepVerdict(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "security_suite", "toolcall", "corpus.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	corpus := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		var row struct {
			ID      string `json:"id"`
			Command string `json:"command"`
		}
		if json.Unmarshal([]byte(line), &row) == nil && row.Command != "" {
			corpus[row.ID] = row.Command
		}
	}
	read, lookup := corpus["sensitive-path-read"], corpus["sensitive-path-targeted-account-check"]
	var sudoers cdFirstTarget
	for _, tg := range cdFirstTargets {
		if tg.name == "sudoers" {
			sudoers = tg
		}
	}
	if read == "" || lookup == "" || sudoers.name == "" {
		t.Fatal("corpus rows or cd-first targets moved")
	}
	file := strings.Fields(read)[1]
	dir, base := filepath.Dir(file), filepath.Base(file)
	// rel 4269debe92 one-step verdicts, tiers default, strict, permissive,
	// managed, managed-strict (evidence/rel-1-0-10/s7/g1058rev rows-rel).
	readTiers := []string{"LM", "LM", "AM", "LM", "LM"}
	oneStep := []struct {
		name, command string
		want          []string
	}{
		{"read", read, readTiers},
		{"targeted account lookup", lookup, []string{"A", "A", "A", "A", "A"}},
		{"touch", "touch " + file, []string{"BC", "BC", "BC", "BC", "BC"}},
	}
	for _, verb := range []string{"head -1", "tail -1", "grep -c x", "sort", "cut -d: -f1", "less", "diff /dev/null", "sudo cat"} {
		oneStep = append(oneStep, struct {
			name, command string
			want          []string
		}{verb, verb + " " + file, readTiers})
	}
	writeOne := strings.ReplaceAll(sudoers.one, "sudoers", base)
	writeIn := strings.ReplaceAll(sudoers.inner, "sudoers", base)
	home := filepath.Join(t.TempDir(), "home", "alice")
	project := filepath.Join(home, "proj")
	if err := os.MkdirAll(filepath.Join(project, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	for pi, p := range gap0437Packs {
		a := gap0437Server(t, p, "claudecode", "action")
		n := 0
		verdict := func(tool string, input map[string]any) string {
			n++
			id := "g1058-" + p.name + "-" + strconv.Itoa(n)
			return shadowLaneVerdict(gap0437Serve(t, a.handleAgentHook("claudecode"), "/api/v1/claude-code/hook", map[string]any{
				"hook_event_name": "PreToolUse", "session_id": id, "cwd": project,
				"tool_name": tool, "tool_use_id": "tu-" + id, "tool_input": input,
			}))
		}
		bash := func(command string) string { return verdict("Bash", map[string]any{"command": command}) }
		for _, row := range oneStep {
			got := bash(row.command)
			if got != row.want[pi] {
				t.Errorf("%s %s: one-step %q is %s, rel gives %s", p.name, row.name, row.command, got, row.want[pi])
			}
			inner := strings.ReplaceAll(row.command, file, base)
			for _, command := range []string{"cd " + dir + " && " + inner, "cd " + dir + "; " + inner, "(cd " + dir + " && " + inner + ")"} {
				if cd := bash(command); cd != got {
					t.Errorf("%s %s: %q is %s, the one-step form is %s", p.name, row.name, command, cd, got)
				}
			}
		}
		one := bash(writeOne)
		for _, command := range []string{"cd " + sudoers.dir + " && " + writeIn, "(cd " + sudoers.dir + "; " + writeIn + ")"} {
			if got := bash(command); got != one {
				t.Errorf("%s: %q is %s, the one-step form %q is %s", p.name, command, got, writeOne, one)
			}
		}
		if strings.HasPrefix(one, "A") {
			t.Errorf("%s: the one-step write %q is %s", p.name, writeOne, one)
		}
		native := verdict("Read", map[string]any{"file_path": file})
		if mcp := verdict("mcp__filesystem__read_file", map[string]any{"path": file}); mcp != native {
			t.Errorf("%s: the MCP read of %s is %s, the native Read is %s", p.name, file, mcp, native)
		}
	}
}
