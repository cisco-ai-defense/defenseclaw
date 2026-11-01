// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package copilotargs

import "testing"

// GAP-2497: a Local body whose Edit (or apply_patch) tool_input is an
// apply_patch text is that apply_patch call; other inputs keep LocalToolArgs.
func TestLocalCallProjectsTheCopilotCLIEditPatchString(t *testing.T) {
	patch := "*** Begin Patch\n*** Update File: b.txt\n@@\n-beta1\n+beta2\n*** End Patch\n"
	for _, tool := range []string{"Edit", "apply_patch"} {
		name, args := LocalCall(tool, patch)
		if name != "apply_patch" || string(args) != `{"patch":"*** Begin Patch\n*** Update File: b.txt\n@@\n-beta1\n+beta2\n*** End Patch\n"}` {
			t.Fatalf("%s: got %s %s", tool, name, args)
		}
	}
	for _, tc := range []struct {
		tool  string
		input any
		want  string
	}{
		{"Edit", "change beta1 to beta2", `"change beta1 to beta2"`},
		{"edit", patch, `"*** Begin Patch\n*** Update File: b.txt\n@@\n-beta1\n+beta2\n*** End Patch\n"`},
		{"Write", patch, `"*** Begin Patch\n*** Update File: b.txt\n@@\n-beta1\n+beta2\n*** End Patch\n"`},
		{"replace_string_in_file", map[string]any{"filePath": "b.txt", "oldString": "beta1", "newString": "beta2"}, `{"content":"beta2","path":"b.txt"}`},
	} {
		name, args := LocalCall(tc.tool, tc.input)
		if name != tc.tool || string(args) != tc.want {
			t.Fatalf("%s %v: got %s %s, want %s %s", tc.tool, tc.input, name, args, tc.tool, tc.want)
		}
	}
}

// GAP-2605: the Copilot CLI sends its create and edit calls to the Local
// hooks as Write and Edit with their native arguments (live capture, Copilot
// CLI 1.0.91 on Windows). Exactly that argument set is the CLI call; any
// other object keeps LocalToolArgs.
func TestLocalCallJudgesTheCopilotCLIWriteAndEditObjectsAsTheirCLICalls(t *testing.T) {
	for _, tc := range []struct {
		tool     string
		input    map[string]any
		wantTool string
		want     string
	}{
		{"Write", map[string]any{"file_text": "delta", "path": `C:\p\p4.txt`}, "create", `{"file_text":"delta","path":"C:\\p\\p4.txt"}`},
		{"Write", map[string]any{"file_text": "delta", "path": "p4.txt", "mode": "0644"}, "create", `{"file_text":"delta","mode":"0644","path":"p4.txt"}`},
		{"Edit", map[string]any{"path": "a.txt", "old_str": "alpha1", "new_str": "alpha2"}, "edit", `{"new_str":"alpha2","old_str":"alpha1","path":"a.txt"}`},
		{"Write", map[string]any{"file_text": "delta", "path": "p4.txt", "extra": "x"}, "Write", `{"extra":"x","file_text":"delta","path":"p4.txt"}`},
		{"Write", map[string]any{"path": "p4.txt"}, "Write", `{"path":"p4.txt"}`},
		{"Write", map[string]any{"file_text": 1, "path": "p4.txt"}, "Write", `{"file_text":1,"path":"p4.txt"}`},
		{"write", map[string]any{"file_text": "delta", "path": "p4.txt"}, "write", `{"file_text":"delta","path":"p4.txt"}`},
		{"create_file", map[string]any{"filePath": "p4.txt", "content": "delta"}, "create_file", `{"content":"delta","path":"p4.txt"}`},
	} {
		name, args := LocalCall(tc.tool, tc.input)
		if name != tc.wantTool || string(args) != tc.want {
			t.Fatalf("%s %v: got %s %s, want %s %s", tc.tool, tc.input, name, args, tc.wantTool, tc.want)
		}
	}
}
