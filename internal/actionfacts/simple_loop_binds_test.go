// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"slices"
	"testing"
)

// rel-1-0-6:GAP-0880: a for variable other than USER and LOGNAME is read once
// for each word of its list that the walk can read, with the value rules of
// an assignment. The reading of the statement that leaves it unread stays.
func TestSimpleCommandsReadLoopVariableWords(t *testing.T) {
	const state = "sed -i x '/r/home/.defenseclaw/config.yaml'"
	const other = "sed -i x '/r/other/.defenseclaw/config.yaml'"
	for _, row := range []struct {
		name, command string
		want, absent  []string
	}{
		{"literal", "for u in home other; do sed -i x /r/$u/.defenseclaw/config.yaml; done", []string{state, other}, nil},
		{"login", "for u in $USER; do sed -i x /r/$u/.defenseclaw/config.yaml; done", []string{state}, nil},
		{"braced", "for u in ${LOGNAME}; do sed -i x /r/$u/.defenseclaw/config.yaml; done", []string{state}, nil},
		{"nested", "for a in $USER; do for u in $a; do sed -i x /r/$u/.defenseclaw/config.yaml; done; done", []string{state}, nil},
		{"unread word", "for u in $(ls) home; do sed -i x /r/$u/.defenseclaw/config.yaml; done", []string{state}, nil},
		{"pattern word stays unread", "for u in h*; do sed -i x /r/$u/.defenseclaw/config.yaml; done", nil, []string{"sed -i x '/r/h*/.defenseclaw/config.yaml'"}},
		{"long list stays unread", "for u in a b c d e f g h i; do sed -i x /r/$u/.defenseclaw/config.yaml; done", nil, []string{"sed -i x '/r/a/.defenseclaw/config.yaml'"}},
		{"body binds the name", "for u in other; do u=home; sed -i x /r/$u/.defenseclaw/config.yaml; done", []string{state}, []string{other}},
		{"read in the body", "for u in other; do read u; sed -i x /r/$u/.defenseclaw/config.yaml; done", nil, []string{other}},
		{"after the loop", "for u in home; do :; done; sed -i x /r/$u/.defenseclaw/config.yaml", nil, []string{state}},
	} {
		t.Run(row.name, func(t *testing.T) {
			input := Input{Tool: "Bash", Command: row.command, ActiveHome: "/r/home", CWD: "/r/home/proj"}
			var got []string
			for _, simple := range SimpleCommands(input, Analyze(input)) {
				if simple.EvaluationFailure != "" {
					t.Fatalf("evaluation failure %q for %s", simple.EvaluationFailure, row.command)
				}
				got = append(got, simple.Text)
				for _, want := range row.want {
					// The reading of an iteration only proves a state write;
					// a statement whose name the body binds is an ordinary one.
					if simple.Text == want && simple.LoginGuess == (row.name == "body binds the name") {
						t.Errorf("%q: LoginGuess = %v", simple.Text, simple.LoginGuess)
					}
				}
			}
			for _, want := range row.want {
				if !slices.Contains(got, want) {
					t.Errorf("%s: missing %q in %q", row.command, want, got)
				}
			}
			for _, absent := range row.absent {
				if slices.Contains(got, absent) {
					t.Errorf("%s: unexpected %q in %q", row.command, absent, got)
				}
			}
		})
	}
}

// rel-1-0-6:GAP-0880, GAP-0885: a while read loop fed by one static echo or
// printf stage binds its variable to that word, as a for loop over it does.
func TestSimpleCommandsReadPipedLoopVariable(t *testing.T) {
	const state = "sed -i x '/r/home/.defenseclaw/config.yaml'"
	for _, row := range []struct {
		name, command string
		reads         bool
	}{
		{"echo", "echo $USER | while read u; do sed -i x /r/$u/.defenseclaw/config.yaml; done", true},
		{"raw", "echo $LOGNAME | while read -r u; do sed -i x /r/$u/.defenseclaw/config.yaml; done", true},
		{"printf", "printf '%s\\n' $USER | while read u; do sed -i x /r/$u/.defenseclaw/config.yaml; done", true},
		{"literal", "echo home | while read u; do sed -i x /r/$u/.defenseclaw/config.yaml; done", true},
		{"two words", "echo $USER other | while read u; do sed -i x /r/$u/.defenseclaw/config.yaml; done", false},
		{"unreadable input", "ls | while read u; do sed -i x /r/$u/.defenseclaw/config.yaml; done", false},
		{"changed IFS", "IFS=x; echo $USER | while read u; do sed -i x /r/$u/.defenseclaw/config.yaml; done", false},
		{"body binds the name", "echo $USER | while read u; do read u; sed -i x /r/$u/.defenseclaw/config.yaml; done", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			input := Input{Tool: "Bash", Command: row.command, ActiveHome: "/r/home", CWD: "/r/home/proj"}
			read := false
			for _, simple := range SimpleCommands(input, Analyze(input)) {
				read = read || simple.Text == state
			}
			if read != row.reads {
				t.Errorf("%s: reading of the state path = %v, want %v", row.command, read, row.reads)
			}
		})
	}
}
