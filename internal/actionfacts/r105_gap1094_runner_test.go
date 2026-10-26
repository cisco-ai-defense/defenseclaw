// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"slices"
	"testing"
)

// GAP-1094: a word naming an exported function in the argv of an ordinary
// program (ls f, or behind a prefix runner: nice ls f, time grep f x) was
// read as a call of the function, so its body was exposed. Only a shell runs
// an exported function by name: the program word itself, a runner that
// hands its words to a shell (watch, parallel, su ...) or an interpreter
// whose code can start one keeps the body exposed.
func TestSimpleCommandsRunnersCallOnlyWhatTheyExecute(t *testing.T) {
	const body = "f() { rm -rf /; }; export -f f; "
	for _, tt := range []struct {
		command string
		ran     bool
	}{
		{body + "ls f", false},
		{body + "nice ls f", false},
		{body + "time grep f x", false},
		{body + "timeout 5 cat f", false},
		{body + "nice f", false},
		{body + "watch f", true},
		{body + "nice watch f", true},
		{body + "parallel f ::: 1", true},
		{body + "su -c f", true},
		{body + "nice bash -c f", true},
		{body + `perl -e "system('f')"`, true},
	} {
		input := Input{Tool: "shell", Command: tt.command, CWD: "/repo", ActiveHome: "/home/alice", DialectHint: DialectPOSIX}
		got := SimpleCommands(input, Analyze(input))
		ran := slices.ContainsFunc(got, func(child SimpleCommand) bool { return child.Text == "rm -rf /" })
		if ran != tt.ran {
			t.Errorf("%q: body exposed = %v, want %v", tt.command, ran, tt.ran)
		}
	}
}
