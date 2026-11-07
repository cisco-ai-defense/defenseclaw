// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"cmp"
	"encoding/json"
	"fmt"
	"slices"
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

// rel-1-0-6:GAP-0729 review 7: a native write call with keys outside the
// schema yields a protected-state call for each target that can reach
// DefenseClaw state or a machine policy file, however many keys come first
// and whether the path is rooted, relative, or an administrative-share
// alias. A key that describes the call or holds the text it writes yields
// none, and a call whose targets are all ordinary files costs no second
// evaluation.
func TestUnknownKeyProtectedStateCalls(t *testing.T) {
	const state = "/sandbox/.defenseclaw/config.yaml"
	many := func(final string) string {
		raw := `{"file_path":"/sandbox/work/app/a.txt","content":"x"`
		for i := 0; i < 12; i++ {
			raw += fmt.Sprintf(`,"a%02d":"/sandbox/work/app/o%d.txt"`, i, i)
		}
		return raw + final + `}`
	}
	for _, test := range []struct {
		name, tool, raw string
		targets         []string
	}{
		{name: "ordinary extras cost nothing", tool: "write", raw: many(``)},
		{name: "a protected key after twelve ordinary ones", tool: "write", raw: many(`,"z":"` + state + `"`), targets: []string{state}},
		{name: "relative key", tool: "write", raw: `{"file_path":"/sandbox/work/app/a.txt","content":"x","f":"../../.defenseclaw/config.yaml"}`, targets: []string{"/sandbox/work/app/../../.defenseclaw/config.yaml"}},
		{name: "reviewed key naming the state", tool: "edit", raw: `{"filePath":"` + state + `","oldString":"a","newString":"b","x":1}`, targets: []string{state}},
		{name: "description mention", tool: "write", raw: `{"file_path":"/sandbox/work/app/a.txt","content":"x","description":"` + state + `"}`},
		{name: "content mention", tool: "write", raw: `{"file_path":"/sandbox/work/app/a.txt","content":"` + state + `","x":1}`},
		{name: "directory key", tool: "write", raw: `{"file_path":"/sandbox/work/app/a.txt","content":"x","cwd":"/sandbox/.defenseclaw"}`},
		{name: "tilde user", tool: "write", raw: `{"file_path":"/sandbox/work/app/a.txt","content":"x","f":"~vn/config.yaml"}`, targets: []string{"~vn/config.yaml"}},
		{name: "managed policy file", tool: "write", raw: `{"file_path":"/sandbox/work/app/a.txt","content":"x","f":"/etc/claude-code/managed-settings.json"}`, targets: []string{"/etc/claude-code/managed-settings.json"}},
		{name: "windows administrative share", tool: "write", raw: `{"file_path":"/sandbox/work/app/a.txt","content":"x","f":"\\\\localhost\\C$\\Program Files\\ClaudeCode\\managed-settings.json"}`, targets: []string{`\\localhost\C$\Program Files\ClaudeCode\managed-settings.json`}},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := Input{Tool: test.tool, Args: json.RawMessage(test.raw), CWD: "/sandbox/work/app", ActiveHome: "/sandbox"}
			calls := UnknownKeyProtectedStateCalls(input, Analyze(input))
			var got []string
			for _, call := range calls {
				var args map[string]string
				if err := json.Unmarshal(call, &args); err != nil {
					t.Fatal(err)
				}
				got = append(got, cmp.Or(args["file_path"], args["path"]))
			}
			if !slices.Equal(got, test.targets) {
				t.Fatalf("protected-state targets = %q, want %q", got, test.targets)
			}
		})
	}
}

// rel-1-0-6:GAP-0729, GAP-0734: every name of a file on the local volume
// is the drive path.
func TestWindowsLocalDrivePath(t *testing.T) {
	for value, want := range map[string]string{
		`C:\Users\vn`:                  "C:/Users/vn",
		`c:/users/vn`:                  "C:/users/vn",
		`\\?\C:\Users\vn`:              "C:/Users/vn",
		`\\.\C:\Users\vn`:              "C:/Users/vn",
		`\\localhost\C$\Users\vn`:      "C:/Users/vn",
		`\\LOCALHOST\c$`:               "C:/",
		`\\127.0.0.1\D$\a\b`:           "D:/a/b",
		`\\127.1.2.3\C$\a`:             "C:/a",
		`\\[::1]\C$\a`:                 "C:/a",
		`\\::1\C$\a`:                   "C:/a",
		`\\?\UNC\localhost\C$\a`:       "C:/a",
		`//./UNC/127.0.0.1/C$/a`:       "C:/a",
		`\\otherhost\C$\a`:             "",
		`\\localhost\share\a`:          "",
		`\\localhost\ADMIN$\a`:         "",
		`\\10.0.0.5\C$\a`:              "",
		`relative\a`:                   "",
		`/etc/codex/requirements.toml`: "",
		`\\localhost`:                  "",
		`\\?\Volume{1234}\a`:           "",
		`\\.\pipe\name`:                "",
		`C:`:                           "",
	} {
		got, ok := WindowsLocalDrivePath(value)
		if (want == "") == ok || got != want && want != "" {
			t.Errorf("WindowsLocalDrivePath(%q) = %q, %t, want %q", value, got, ok, want)
		}
	}
}
