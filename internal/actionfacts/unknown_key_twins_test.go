// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// TestUnknownKeyTwinsNameEveryTargetTheCallCanReach pins the readings of
// file-tool calls with keys outside their reviewed schema (gas-ux-r1
// GAP-0076): the call without those keys, keeping its text, and each
// path-shaped value they hold, at any depth, as the same tool's target.
// Reads, writes, edits, notebook edits and patch envelopes are all read;
// free text, URLs and complete calls add no reading.
func TestUnknownKeyTwinsNameEveryTargetTheCallCanReach(t *testing.T) {
	const (
		state = "/sandbox/.defenseclaw/config.yaml"
		notes = "/sandbox/work/app/notes.txt"
	)
	patch := func(p string) string {
		return "*** Begin Patch\n*** Update File: " + p + "\n@@\n-a\n+b\n*** End Patch\n"
	}
	encode := func(v any) string {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	for _, test := range []struct {
		name, tool, raw string
		access          PathAccess
		targets         []string
		overflow        bool
	}{
		{name: "claude write + description", tool: "Write", raw: encode(map[string]any{"file_path": state, "content": "k", "description": "d"}), access: PathAccessWrite, targets: []string{state}},
		{name: "opencode write filePath + description", tool: "write", raw: encode(map[string]any{"filePath": state, "content": "k", "description": "d"}), access: PathAccessWrite, targets: []string{state}},
		{name: "opencode edit + two keys", tool: "edit", raw: encode(map[string]any{"filePath": state, "oldString": "a", "newString": "b", "description": "d", "timeout": 5}), access: PathAccessWrite, targets: []string{state}},
		{name: "notebook edit + key", tool: "NotebookEdit", raw: encode(map[string]any{"notebook_path": state, "new_source": "x", "cell_id": "c", "cell_type": "code", "edit_mode": "replace", "x": 1}), access: PathAccessWrite, targets: []string{state}},
		{name: "apply_patch patchText + description", tool: "apply_patch", raw: encode(map[string]any{"patchText": patch(state), "description": "d"}), access: PathAccessWrite, targets: []string{state}},
		{name: "codex apply_patch command + key", tool: "apply_patch", raw: encode(map[string]any{"command": patch(state), "x": true}), access: PathAccessWrite, targets: []string{state}},
		{name: "read + key", tool: "Read", raw: encode(map[string]any{"file_path": state, "x": 1}), access: PathAccessRead, targets: []string{state}},
		{name: "hidden under an unknown key", tool: "Write", raw: encode(map[string]any{"file_path": notes, "content": "k", "target_file": state}), access: PathAccessWrite, targets: []string{notes, state}},
		{name: "hidden in a nested object", tool: "edit", raw: encode(map[string]any{"filePath": notes, "oldString": "a", "newString": "b", "options": map[string]any{"dest": map[string]any{"to": state}}}), access: PathAccessWrite, targets: []string{notes, state}},
		{name: "hidden in an array", tool: "apply_patch", raw: encode(map[string]any{"patchText": patch(notes), "extra": []any{"x", state}}), access: PathAccessWrite, targets: []string{notes, state}},
		{name: "hidden home form", tool: "Write", raw: encode(map[string]any{"file_path": notes, "content": "k", "f": "~/.defenseclaw/config.yaml"}), access: PathAccessWrite, targets: []string{notes, state}},
		{name: "case twin of the target key", tool: "Edit", raw: encode(map[string]any{"file_path": notes, "old_string": "a", "new_string": "b", "FILE_PATH": state}), access: PathAccessWrite, targets: []string{notes, state}},
		{name: "free text and URL are no target", tool: "Write", raw: encode(map[string]any{"file_path": notes, "content": "k", "description": "update the notes", "link": "https://example.com/a/b"}), access: PathAccessWrite, targets: []string{notes}},
		{name: "complete call has no reading", tool: "Write", raw: encode(map[string]any{"file_path": state, "content": "k"})},
		{name: "shell tool has no reading", tool: "Bash", raw: encode(map[string]any{"command": "true", "description": state})},
		{name: "past the bound", tool: "Write", raw: encode(map[string]any{"file_path": notes, "content": "k", "files": distinctPaths(17)}), access: PathAccessWrite, overflow: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := Input{Tool: test.tool, Args: json.RawMessage(test.raw), CWD: "/sandbox/work/app", ActiveHome: "/sandbox"}
			facts := Analyze(input)
			twins, overflow := UnknownKeyTwins(input, facts)
			if overflow != test.overflow {
				t.Fatalf("overflow = %t, want %t", overflow, test.overflow)
			}
			if test.overflow {
				if !UnknownKeyWriteOverflow(input, facts) {
					t.Fatal("a write past the bound must report the overflow")
				}
				return
			}
			var got []string
			for _, twin := range twins {
				if !twin.Facts.Authoritative() || twin.Facts.Tool != test.tool {
					t.Fatalf("reading %s: tool=%q parse=%+v", twin.Args, twin.Facts.Tool, twin.Facts.Parse)
				}
				for _, path := range twin.Facts.Paths {
					if path.Access == test.access && !slices.Contains(got, path.Resolved) {
						got = append(got, path.Resolved)
					}
				}
			}
			if !slices.Equal(got, test.targets) {
				t.Fatalf("parse=%+v readings=%d targets=%q, want %q", facts.Parse, len(twins), got, test.targets)
			}
			if len(test.targets) != 0 && facts.Parse.Status != StatusPartial {
				t.Fatalf("the call itself must stay partial: %+v", facts.Parse)
			}
		})
	}
}

// TestUnknownKeyTwinsKeepTheReviewedText pins that the reading without the
// unknown keys is the call's own reviewed arguments, text included, so the
// content rules judge what the harness writes.
func TestUnknownKeyTwinsKeepTheReviewedText(t *testing.T) {
	raw := json.RawMessage(`{"file_path":"/etc/sudoers.d/x","content":"alice ALL=(ALL) NOPASSWD: ALL\n","description":"d"}`)
	input := Input{Tool: "Write", Args: raw, CWD: "/w", ActiveHome: "/home/alice"}
	twins, _ := UnknownKeyTwins(input, Analyze(input))
	if len(twins) == 0 {
		t.Fatal("no reading")
	}
	var reduced map[string]any
	if err := json.Unmarshal(twins[0].Args, &reduced); err != nil {
		t.Fatal(err)
	}
	if _, ok := reduced["description"]; ok || reduced["content"] != "alice ALL=(ALL) NOPASSWD: ALL\n" {
		t.Fatalf("reduced reading = %s", twins[0].Args)
	}
}

func distinctPaths(n int) []any {
	out := make([]any, 0, n)
	for i := range n {
		out = append(out, fmt.Sprintf("/tmp/out/f%d.txt", i))
	}
	return out
}

// TestUnknownKeyTwinsJoinTheHomeInTheConnectorDialect pins that a home form
// under an unknown key joins ActiveHome with slashes whatever the gateway
// host is (a Windows gateway joined /sandbox as \sandbox, which then
// resolved under the cwd and hid the DefenseClaw state file), and that a
// Windows-form call resolves its state file too.
func TestUnknownKeyTwinsJoinTheHomeInTheConnectorDialect(t *testing.T) {
	for _, test := range []struct{ name, cwd, home, value, want string }{
		{"posix home form", "/sandbox/work/app", "/sandbox", "~/.defenseclaw/config.yaml", "/sandbox/.defenseclaw/config.yaml"},
		{"posix $HOME form", "/sandbox/work/app", "/sandbox", "$HOME/.defenseclaw/config.yaml", "/sandbox/.defenseclaw/config.yaml"},
		{"windows home form", `C:\Users\x\work`, `C:\Users\x`, "~/.defenseclaw/config.yaml", "C:/Users/x/.defenseclaw/config.yaml"},
		{"windows literal path", `C:\Users\x\work`, `C:\Users\x`, `C:\Users\x\.defenseclaw\config.yaml`, "C:/Users/x/.defenseclaw/config.yaml"},
	} {
		t.Run(test.name, func(t *testing.T) {
			notes := test.cwd + "/notes.txt"
			if strings.Contains(test.cwd, `\`) {
				notes = test.cwd + `\` + "notes.txt"
			}
			raw, err := json.Marshal(map[string]any{"file_path": notes, "content": "k", "f": test.value})
			if err != nil {
				t.Fatal(err)
			}
			input := Input{Tool: "Write", Args: raw, CWD: test.cwd, ActiveHome: test.home}
			twins, _ := UnknownKeyTwins(input, Analyze(input))
			var got []string
			for _, twin := range twins {
				for _, path := range twin.Facts.Paths {
					if path.Access == PathAccessWrite {
						got = append(got, path.Resolved)
					}
				}
			}
			if !slices.Contains(got, test.want) {
				t.Fatalf("write targets = %q, want one of them to be %q", got, test.want)
			}
		})
	}
}
