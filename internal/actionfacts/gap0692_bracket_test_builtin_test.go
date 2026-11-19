// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestGAP0692BracketTestKeepsTheCallSplit: a `[ ... ]` test anywhere in an
// action that defines a function is a call of the test builtin, like `test`.
// The per-command split reads the action as it reads the `test` spelling,
// so the protected write after it is judged as its own command
// (substrate-1:GAP-0692: the split gave up on the unmatched glob opener of
// `[`, and `f(){ [ -e .bashrc ]; }; f && echo x >> ~/.bashrc` was a clean
// allow at rel, where the `test -e` form alerts).
func TestGAP0692BracketTestKeepsTheCallSplit(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home", "alice")
	testForm := strings.NewReplacer("[[ ", "test ", " ]]", "", "[ ", "test ", " ]", "")
	rows := []struct{ name, command, write string }{
		{"body", "f(){ [ -e .bashrc ]; }; f && echo x >> .bashrc", "echo x >> .bashrc"},
		{"body and", "f(){ [ -e .bashrc ] && :; }; f && echo x >> .zshrc", "echo x >> .zshrc"},
		{"body return", "f(){ [ -e .bashrc ] && return 0; cd /tmp; }; f && echo x >> .bashrc", "echo x >> .bashrc"},
		{"body or cd", "f(){ [ -e .bashrc ] || cd /tmp; }; f && echo x >> .profile", "echo x >> .profile"},
		{"negated", "f(){ ! [ -e .bashrc ]; }; f && echo x >> .profile", "echo x >> .profile"},
		{"command prefix", "f(){ command [ -e .bashrc ]; }; f && echo x >> .bashrc", "echo x >> .bashrc"},
		{"builtin prefix", "f(){ builtin [ -e .bashrc ]; }; f; echo x >> .bashrc", "echo x >> .bashrc"},
		{"nested function", "f(){ g(){ [ -e .bashrc ]; }; g; }; f && echo x >> .bashrc", "echo x >> .bashrc"},
		{"top level", "g(){ :; }; [ -e .bashrc ]; echo x >> .bashrc", "echo x >> .bashrc"},
		{"uncalled body", "g(){ [ a ]; }; echo x >> .bashrc", "echo x >> .bashrc"},
		{"copy", "f(){ [ -f /tmp/x ]; }; f && cp /tmp/x .bashrc", "cp /tmp/x .bashrc"},
		{"credential copy", "f(){ [ -e .aws/credentials ]; }; f && cp .aws/credentials /tmp/staged", "cp .aws/credentials /tmp/staged"},
		{"double bracket", "f(){ [[ -e .bashrc ]]; }; f && echo x >> .bashrc", "echo x >> .bashrc"},
	}
	type reading struct{ text, cwd, failure string }
	split := func(command string, straight bool) []reading {
		args, _ := json.Marshal(map[string]string{"command": command})
		input := Input{Tool: "Bash", Args: args, CWD: home, StraightLineFunctions: straight}
		var readings []reading
		for _, simple := range SimpleCommands(input, Analyze(input)) {
			readings = append(readings, reading{testForm.Replace(simple.Text), simple.CWD, simple.EvaluationFailure})
		}
		return readings
	}
	for _, straight := range []bool{true, false} {
		for _, row := range rows {
			got, want := split(row.command, straight), split(testForm.Replace(row.command), straight)
			if !slices.Equal(got, want) {
				t.Errorf("straight=%v %s: %q splits as %+v, its test form as %+v", straight, row.name, row.command, got, want)
			}
			if !slices.Contains(got, reading{row.write, home, ""}) {
				t.Errorf("straight=%v %s: %q: no reading %q in the home: %+v", straight, row.name, row.command, row.write, got)
			}
		}
	}
}
