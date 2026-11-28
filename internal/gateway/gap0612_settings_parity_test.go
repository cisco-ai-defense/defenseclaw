// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import "strings"

// Saved RVNF7 probe rows are permanent assertions in the API parity table,
// with and without snapshots, for copy and mount actors.
func gapNF8ReviewRows() []gapNF6ParityRow {
	base := gap0433LaptopSettings
	with := func(m string) string { return "{" + m + "," + base[1:] }
	reg := base[len(`{"hooks":`) : len(base)-1]
	U, L, P := "{H}/.claude/settings.json", "{H}/.claude/settings.local.json", "{P}/.claude/settings.json"
	rows := []struct {
		name, rel, file, tool string
		input                 map[string]any
	}{
		{"U1 benign model exact", ".claude/settings.json", with(`"model":"zzz"`), "Edit", map[string]any{"file_path": U, "old_string": `"zzz"`, "new_string": `"yyy"`}},
		{"U2 add switch", ".claude/settings.json", with(`"model":"zzz"`), "Edit", map[string]any{"file_path": U, "old_string": `"model":"zzz"`, "new_string": `"model":"zzz","disableAllHooks":true`}},
		{"U3 empty old on nonempty", ".claude/settings.json", with(`"model":"zzz"`), "Edit", map[string]any{"file_path": U, "old_string": ``, "new_string": `{"disableAllHooks":true}`}},
		{"U4 multiedit idx1 empty old", ".claude/settings.json", with(`"model":"zzz"`), "MultiEdit", map[string]any{"file_path": U, "edits": []any{
			map[string]any{"old_string": `"zzz"`, "new_string": `"yyy"`}, map[string]any{"old_string": ``, "new_string": `{"disableAllHooks":true}`}}}},
		{"U5 multiedit set then restore", ".claude/settings.json", with(`"disableAllHooks":false`), "MultiEdit", map[string]any{"file_path": U, "edits": []any{
			map[string]any{"old_string": `"disableAllHooks":false`, "new_string": `"disableAllHooks":true`}, map[string]any{"old_string": `"disableAllHooks":true`, "new_string": `"disableAllHooks":false`}}}},
		{"U6 multiedit final invalid", ".claude/settings.json", with(`"model":"zzz"`), "MultiEdit", map[string]any{"file_path": U, "edits": []any{
			map[string]any{"old_string": `"zzz"`, "new_string": `"yyy"`}, map[string]any{"old_string": `"yyy"`, "new_string": `"yyy",`}}}},
		{"U7 identity escape reserved value", ".claude/settings.json", with(`"env":{"LD_PRELOAD":"/opt/a"}`), "Edit", map[string]any{"file_path": U, "old_string": `"/opt/a"`, "new_string": `"\/opt\/a"`}},
		{"U8 identity replace_all", ".claude/settings.json", with(`"env":{"LD_PRELOAD":"a"},"model":"a"`), "Edit", map[string]any{"file_path": U, "old_string": `"a"`, "new_string": `"a"`, "replace_all": true}},
		{"U9 write keep hooks benign", ".claude/settings.json", base, "Write", map[string]any{"file_path": U, "content": `{"env":{"ORDINARY":"1"},"hooks":` + reg + `}`}},
		{"U10 write dup hooks key", ".claude/settings.json", base, "Write", map[string]any{"file_path": U, "content": `{"hooks":` + reg + `,"hooks":{}}`}},
		{"U11 write switch string", ".claude/settings.json", base, "Write", map[string]any{"file_path": U, "content": `{"disableAllHooks":"false","hooks":` + reg + `}`}},
		{"U12 write reserved env", ".claude/settings.json", base, "Write", map[string]any{"file_path": U, "content": `{"env":{"BASH_ENV":"/tmp/x"},"hooks":` + reg + `}`}},
		{"U13 edit value only to reserved", ".claude/settings.json", with(`"env":{"BASH_ENV":"/opt/a"}`), "Edit", map[string]any{"file_path": U, "old_string": `/opt/a`, "new_string": `/tmp/x`}},
		{"U14 empty file create switch", ".claude/settings.json", "", "Edit", map[string]any{"file_path": U, "old_string": ``, "new_string": `{"disableAllHooks":true}`}},
		{"U15 broken file repair to switch", ".claude/settings.json", `{"model":"x",}`, "Edit", map[string]any{"file_path": U, "old_string": `"x",}`, "new_string": `"x","disableAllHooks":true}`}},
		{"U16 multiedit drop hooks via two steps", ".claude/settings.json", with(`"model":"zzz"`), "MultiEdit", map[string]any{"file_path": U, "edits": []any{
			map[string]any{"old_string": `"PreToolUse"`, "new_string": `"PreToolUsX"`}, map[string]any{"old_string": `UsX"`, "new_string": `Use_"`}}}},
		{"L1 local add switch", ".claude/settings.local.json", with(`"model":"zzz"`), "Edit", map[string]any{"file_path": L, "old_string": `"model":"zzz"`, "new_string": `"model":"zzz","disableAllHooks":true`}},
		{"L2 local write empty", ".claude/settings.local.json", base, "Write", map[string]any{"file_path": L, "content": `{}`}},
		{"P1 project add switch", "proj/.claude/settings.json", with(`"model":"zzz"`), "Edit", map[string]any{"file_path": P, "old_string": `"model":"zzz"`, "new_string": `"model":"zzz","disableAllHooks":true`}},
		{"P2 project write empty", "proj/.claude/settings.json", base, "Write", map[string]any{"file_path": P, "content": `{}`}},
		{"P3 project value to reserved", "proj/.claude/settings.json", with(`"env":{"BASH_ENV":"/opt/a"}`), "Edit", map[string]any{"file_path": P, "old_string": `/opt/a`, "new_string": `/tmp/x`}},
	}
	var result []gapNF6ParityRow
	for _, r := range rows {
		want, noCopy := "block", "block"
		switch r.name[:2] {
		case "U1":
			// U10..U16 remain blocks; U1 and U13 differ.
			if r.name[2] == ' ' {
				want = "allow"
			}
		case "U3", "U4":
			want = "alert"
		case "U5":
			want = "allow"
		case "U7", "U8":
			want, noCopy = "allow", "allow"
		case "U9":
			// The laptop file is the one-entry fallback document, not what
			// Setup writes: without a snapshot the actor requires Setup's
			// full hook set (substrate-1 GAP-0615; the real-setup row is
			// TestGAP0615GuestHookConfigParity C1_control_Write_keeps_all_hooks).
			want, noCopy = "allow", "block"
		}
		result = append(result, gapNF6ParityRow{name: "rvnf7 " + r.name, target: r.rel, file: r.file, tool: r.tool, input: r.input, want: want, noCopy: noCopy})
	}
	// Extend every required shape to all four laptop/kit settings paths,
	// including project settings.local.json which RVNF7 did not probe.
	for _, rel := range []string{".claude/settings.json", ".claude/settings.local.json", "proj/.claude/settings.json", "proj/.claude/settings.local.json"} {
		for _, shape := range []struct{ name, file, tool, old, next, want, noCopy string }{
			{"add switch", with(`"model":"zzz"`), "Edit", `"model":"zzz"`, `"model":"zzz","disableAllHooks":true`, "block", "block"},
			{"drop hooks", base, "Write", "", "{}", "block", "block"},
			{"reserved env value", with(`"env":{"BASH_ENV":"/opt/a"}`), "Edit", "/opt/a", "/tmp/x", "block", "block"},
			{"byte no-op", with(`"model":"zzz"`), "Edit", `"zzz"`, `"zzz"`, "allow", "allow"},
			{"equivalent string", with(`"model":"zzz"`), "Edit", `"zzz"`, `"zz\u007a"`, "allow", "allow"},
		} {
			target := "{H}/" + rel
			if strings.HasPrefix(rel, "proj/") {
				target = "{P}/" + strings.TrimPrefix(rel, "proj/")
			}
			input := map[string]any{"file_path": target}
			if shape.tool == "Write" {
				input["content"] = shape.next
			} else {
				input["old_string"], input["new_string"] = shape.old, shape.next
			}
			result = append(result, gapNF6ParityRow{name: "nf8 " + rel + " " + shape.name, target: rel, file: shape.file, tool: shape.tool, input: input, want: shape.want, noCopy: shape.noCopy})
		}
	}
	return result
}
