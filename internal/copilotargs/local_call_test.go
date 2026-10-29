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
