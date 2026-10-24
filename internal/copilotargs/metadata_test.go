// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package copilotargs

import "testing"

// Only the metadata field of a Copilot CLI edit or create is dropped, and
// only when every other field is a reviewed one; any other call keeps its
// arguments.
func TestWriteArgsWithoutMetadata(t *testing.T) {
	for _, row := range []struct {
		name, tool, args, want string
	}{
		{"edit description", "edit", `{"path":"a","old_str":"x","new_str":"y","description":"d"}`, `{"new_str":"y","old_str":"x","path":"a"}`},
		{"create mode", "create", `{"path":"a","file_text":"x","mode":"0600"}`, `{"file_text":"x","path":"a"}`},
		{"edit without metadata", "edit", `{"path":"a","old_str":"x","new_str":"y"}`, ""},
		{"edit with an unknown field", "edit", `{"path":"a","old_str":"x","new_str":"y","description":"d","target":"b"}`, ""},
		{"create with a second target key", "create", `{"path":"a","filePath":"b","file_text":"x","mode":"0600"}`, ""},
		{"mode on edit", "edit", `{"path":"a","old_str":"x","new_str":"y","mode":"0600"}`, ""},
		{"description on create", "create", `{"path":"a","file_text":"x","description":"d"}`, ""},
		{"another tool", "create_file", `{"filePath":"a","content":"x","mode":"0600"}`, ""},
		{"capitalized tool", "Edit", `{"path":"a","old_str":"x","new_str":"y","description":"d"}`, ""},
		{"not an object", "edit", `["description"]`, ""},
	} {
		t.Run(row.name, func(t *testing.T) {
			got, ok := WriteArgsWithoutMetadata(row.tool, []byte(row.args))
			if ok != (row.want != "") || string(got) != row.want {
				t.Fatalf("WriteArgsWithoutMetadata = %s, %t; want %q", got, ok, row.want)
			}
		})
	}
}
