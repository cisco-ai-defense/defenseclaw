// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"testing"
)

// TestUnknownKeyWriteTargetViews pins the target views of native write
// tool calls with an argument outside their reviewed schema: the call stays
// partial, and each view is the complete analysis of the same tool writing
// the target it names (GAP-0655).
func TestUnknownKeyWriteTargetViews(t *testing.T) {
	const keys = "/sandbox/.ssh/authorized_keys"
	for _, test := range []struct {
		name, tool, raw string
		command         string
		targets         []string
	}{
		{name: "opencode edit", tool: "edit", raw: `{"filePath":"` + keys + `","oldString":"a","newString":"b","description":"d"}`, targets: []string{keys}},
		{name: "opencode write", tool: "write", raw: `{"filePath":"` + keys + `","content":"k","description":"d"}`, targets: []string{keys}},
		{name: "copilot edit", tool: "edit", raw: `{"path":"` + keys + `","old_str":"a","new_str":"b","description":"d"}`, targets: []string{keys}},
		{name: "copilot create", tool: "create", raw: `{"path":"` + keys + `","file_text":"k","mode":"0600"}`, targets: []string{keys}},
		{name: "claude multiedit", tool: "MultiEdit", raw: `{"file_path":"` + keys + `","edits":[{"old_string":"a","new_string":"b"}],"x":1}`, targets: []string{keys}},
		{name: "relative target", tool: "edit", raw: `{"filePath":"../../.ssh/authorized_keys","oldString":"a","newString":"b","x":true}`, targets: []string{"/sandbox/.ssh/authorized_keys"}},
		{name: "two target keys", tool: "edit", raw: `{"filePath":"/work/app/a.txt","path":"` + keys + `","oldString":"a","newString":"b"}`, targets: []string{"/work/app/a.txt", keys}},
		{name: "complete call has no view", tool: "edit", raw: `{"filePath":"` + keys + `","oldString":"a","newString":"b"}`},
		{name: "read tool has no view", tool: "read", raw: `{"filePath":"` + keys + `","limit":1,"x":1}`},
		{name: "non-string target", tool: "write", raw: `{"filePath":["` + keys + `"],"content":"k","x":1}`},
		{name: "empty target", tool: "write", raw: `{"filePath":" ","content":"k","x":1}`},
		{name: "duplicate key", tool: "write", raw: `{"filePath":"/work/app/a.txt","filePath":"` + keys + `","content":"k","x":1}`},
		{name: "command text", tool: "write", raw: `{"filePath":"` + keys + `","content":"k","x":1}`, command: "true"},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := Input{Tool: test.tool, Args: json.RawMessage(test.raw), Command: test.command, CWD: "/sandbox/work/app", ActiveHome: "/sandbox"}
			facts := Analyze(input)
			views := UnknownKeyWriteTargetViews(input, facts)
			if len(views) != len(test.targets) {
				t.Fatalf("parse=%+v: %d views, want %d", facts.Parse, len(views), len(test.targets))
			}
			if len(test.targets) != 0 && facts.Parse.Status != StatusPartial {
				t.Fatalf("the call itself must stay partial: %+v", facts.Parse)
			}
			for i, view := range views {
				if !view.Authoritative() || view.Tool != test.tool {
					t.Fatalf("view %d: tool=%q parse=%+v", i, view.Tool, view.Parse)
				}
				found := false
				for _, path := range view.Paths {
					if path.Access == PathAccessWrite && path.Resolved == test.targets[i] {
						found = true
					}
				}
				if !found {
					t.Fatalf("view %d paths=%+v, want a write of %s", i, view.Paths, test.targets[i])
				}
			}
		})
	}
}
