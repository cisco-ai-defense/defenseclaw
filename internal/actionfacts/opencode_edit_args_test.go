// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"testing"
)

// OpenCode V2 edit takes path with camelCase replacement keys. Shared
// filePath-based formats and Copilot CLI path/old_str/new_str or file_text
// remain covered independently of connector version admission. Each dialect
// parses as a complete write call with one target, like Claude Code's (GAP-0655).
func TestExtractOpenCodeEditArgs(t *testing.T) {
	const keys = "/sandbox/.ssh/authorized_keys"
	for _, test := range []struct {
		name, tool, raw string
		want            ParseStatus
		path            string
	}{
		{name: "edit", tool: "edit", raw: `{"path":"` + keys + `","oldString":"# a","newString":"# a\nk"}`, want: StatusComplete, path: keys},
		{name: "edit replace all", tool: "edit", raw: `{"path":"` + keys + `","oldString":"# a","newString":"k","replaceAll":true}`, want: StatusComplete, path: keys},
		{name: "multiedit", tool: "multiedit", raw: `{"filePath":"` + keys + `","edits":[{"oldString":"# a","newString":"k"}]}`, want: StatusComplete, path: keys},
		// The shared camelCase multiedit format applies the call's own path.
		{name: "multiedit item path", tool: "multiedit", raw: `{"filePath":"` + keys + `","edits":[{"filePath":"/work/app/a.txt","oldString":"# a","newString":"k","replaceAll":false}]}`, want: StatusComplete, path: keys},
		{name: "copilot edit", tool: "edit", raw: `{"path":"` + keys + `","old_str":"# a","new_str":"k"}`, want: StatusComplete, path: keys},
		{name: "copilot create", tool: "create", raw: `{"path":"` + keys + `","file_text":"k"}`, want: StatusComplete, path: keys},
		{name: "copilot edit replace all", tool: "edit", raw: `{"path":"` + keys + `","old_str":"# a","new_str":"k","replace_all":true}`, want: StatusPartial},
		// An argument outside the schema keeps the call partial; its target
		// is judged by UnknownKeyWriteTargetViews.
		{name: "create unknown field", tool: "create", raw: `{"path":"` + keys + `","file_text":"k","mode":"0600"}`, want: StatusPartial},
		{name: "snake edit unchanged", tool: "Edit", raw: `{"file_path":"` + keys + `","old_string":"# a","new_string":"k"}`, want: StatusComplete, path: keys},
		{name: "v2 mixed path keys", tool: "edit", raw: `{"path":"` + keys + `","file_path":"/other","oldString":"# a","newString":"k"}`, want: StatusPartial},
		{name: "v2 mixed replacement keys", tool: "edit", raw: `{"path":"` + keys + `","old_string":"# a","newString":"k"}`, want: StatusPartial},
		{name: "v2 invalid replace all", tool: "edit", raw: `{"path":"` + keys + `","oldString":"# a","newString":"k","replaceAll":"yes"}`, want: StatusPartial},
		{name: "mixed dialect", tool: "edit", raw: `{"filePath":"` + keys + `","old_string":"# a","newString":"k"}`, want: StatusPartial},
		{name: "snake item path", tool: "MultiEdit", raw: `{"file_path":"` + keys + `","edits":[{"filePath":"` + keys + `","old_string":"# a","new_string":"k"}]}`, want: StatusPartial},
		{name: "missing new text", tool: "edit", raw: `{"filePath":"` + keys + `","oldString":"# a"}`, want: StatusPartial},
		{name: "wrong replace all type", tool: "edit", raw: `{"filePath":"` + keys + `","oldString":"# a","newString":"k","replaceAll":"yes"}`, want: StatusPartial},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := extractArgsForTool(json.RawMessage(test.raw), test.tool)
			if got.status != test.want {
				t.Fatalf("status=%s issues=%v", got.status, got.issues)
			}
			if test.path == "" {
				return
			}
			if len(got.paths) != 1 || got.paths[0].key != "path" || got.paths[0].value != test.path {
				t.Fatalf("paths=%+v", got.paths)
			}
			if len(got.payload) == 0 || got.payload[0].key != "content" || !got.payload[0].nonEmpty {
				t.Fatalf("payload=%+v", got.payload)
			}
		})
	}
}
