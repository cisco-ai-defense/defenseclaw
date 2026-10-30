// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// The hook client read a tool call with ~/ through the active-user tilde
// twin, whose parser recursed per level of ( before any nesting bound: cat
// ~/a.txt and 180 KiB of ( overflowed the 1 GB goroutine stack, a fatal
// error in the hook process (GAP-2556, the GAP-2537 class). Such a body is
// described as incomplete evidence at once, a body that hides its ( behind
// JSON escapes is still refused by every parser, and ordinary nesting keeps
// its targets. The stack bound makes the old recursion fail on every OS.
func TestResolveConnectorBoundsDeepNesting(t *testing.T) {
	defer debug.SetMaxStack(debug.SetMaxStack(64 << 20))
	home := t.TempDir()
	for _, unit := range []string{"(", "$(", "$((", "{ ", "\"$(", "["} {
		command := "cat ~/a.txt\n" + strings.Repeat(unit, (180<<10)/len(unit)) + "\ncat ~/.defenseclaw/config.yaml"
		payload, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": home,
			"tool_input": map[string]any{"command": command}})
		if err != nil {
			t.Fatal(err)
		}
		for _, connector := range []string{"claudecode", "codex"} {
			start := time.Now()
			targets, ok := Decode(ResolveConnector(connector, "", "PreToolUse", payload))
			if took := time.Since(start); took > 3*time.Second {
				t.Errorf("%s unit %q: resolved in %s", connector, unit, took)
			}
			if !ok || targets[TruncatedKey] != "1" {
				t.Errorf("%s unit %q: targets %v, want incomplete evidence", connector, unit, targets)
			}
		}
		escaped := strings.ReplaceAll(string(payload), "(", `\u0028`)
		escaped = strings.ReplaceAll(escaped, "{ ", `\u007b `)
		escaped = strings.ReplaceAll(escaped, "[", `\u005b`)
		if len(escaped) <= MaxPayloadBytes {
			_ = ResolveConnector("claudecode", "", "PreToolUse", []byte(escaped))
		}
		if _, _, ok := actionfacts.ActiveUserTildeTwin(command, home, "alice"); ok {
			t.Errorf("unit %q: tilde twin of a deep command", unit)
		}
	}
	nested := strings.Repeat("( ", 8) + "cat ~/a.txt > out.txt" + strings.Repeat(" )", 8)
	payload, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": home,
		"tool_input": map[string]any{"command": nested}})
	if err != nil {
		t.Fatal(err)
	}
	if targets, _ := Decode(ResolveConnector("claudecode", "", "PreToolUse", payload)); targets[TruncatedKey] == "1" {
		t.Errorf("8-level subshell: incomplete evidence %v", targets)
	}
}

// The nesting bound measures the shell command only. A managed Write or Edit
// of an ordinary file whose text has many unclosed (, { or [ (an ANSI colour
// escape ESC[31m is one) is not shell: it keeps its target and complete
// evidence, so the managed gateway does not fail it closed (RV-p4-1 of
// GAP-2556, BALANCED-DEFAULTS).
func TestResolveConnectorDeepTextBodyIsNotShell(t *testing.T) {
	home := t.TempDir()
	target := home + "/project/ordinary/log.txt"
	colored := strings.Repeat("\x1b[31mERROR\x1b[0m build step failed\n", 600)
	for _, row := range []struct {
		name string
		tool string
		args map[string]any
	}{
		{"W1 colored Write", "Write", map[string]any{"file_path": target, "content": colored}},
		{"W2 Write of (", "Write", map[string]any{"file_path": target, "content": strings.Repeat("(", 600)}},
		{"W4 relative Write", "Write", map[string]any{"file_path": "project/ordinary/log.txt", "content": strings.Repeat("(", 600)}},
		{"E1 colored Edit", "Edit", map[string]any{"file_path": target, "old_string": "x", "new_string": colored}},
	} {
		payload, err := json.Marshal(map[string]any{"tool_name": row.tool, "cwd": home, "tool_input": row.args})
		if err != nil {
			t.Fatal(err)
		}
		targets, ok := Decode(ResolveConnector("claudecode", "", "PreToolUse", payload))
		if !ok || targets[TruncatedKey] == "1" {
			t.Errorf("%s: targets %v, want complete evidence", row.name, targets)
		}
	}
}

// The command of a Codex apply_patch call is a patch envelope. A patch that
// adds ordinary text with more than shellparse.MaxNestingDepth unclosed (, {
// or [ (ANSI colour escapes) keeps complete evidence and its targets, as the
// same patch under input does (GAP-2561, the RV-p4-1 class).
func TestResolveConnectorDeepPatchBodyIsNotShell(t *testing.T) {
	defer debug.SetMaxStack(debug.SetMaxStack(64 << 20))
	home := t.TempDir()
	cwd := home + "/project"
	target := cwd + "/testdata/log.golden"
	patch := func(path, body string) string {
		return "*** Begin Patch\n*** Add File: " + path + "\n" + body + "*** End Patch\n"
	}
	colored := strings.Repeat("+\x1b[31mERROR\x1b[0m build step failed\n", 600)
	for _, row := range []struct {
		name, key, body, path string
	}{
		{"H01 colored command", "command", colored, target},
		{"H02 colored input", "input", colored, target},
		{"P02 600 (", "command", strings.Repeat("+(\n", 600), target},
		{"P07 520 [", "command", "+" + strings.Repeat("[", 520) + "\n", target},
		{"K1 colored key patch", "command", colored, home + "/.ssh/authorized_keys"},
	} {
		payload, err := json.Marshal(map[string]any{"tool_name": "apply_patch", "cwd": cwd,
			"tool_input": map[string]any{row.key: patch(row.path, row.body)}})
		if err != nil {
			t.Fatal(err)
		}
		targets, ok := Decode(ResolveConnector("codex", "", "PreToolUse", payload))
		if !ok || targets[TruncatedKey] == "1" {
			t.Errorf("%s: targets %v, want complete evidence", row.name, targets)
		}
		if _, listed := targets[row.path]; !listed {
			t.Errorf("%s: targets %v, want %s", row.name, targets, row.path)
		}
	}
	// A deep shell command is still past the bound.
	payload, _ := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": cwd,
		"tool_input": map[string]any{"command": "cat ~/a.txt\n" + strings.Repeat("(", 180<<10)}})
	if targets, _ := Decode(ResolveConnector("codex", "", "PreToolUse", payload)); targets[TruncatedKey] != "1" {
		t.Errorf("deep Bash: targets %v, want incomplete evidence", targets)
	}
}
