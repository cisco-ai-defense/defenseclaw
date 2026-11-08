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
		{"twelve words are read", "for u in a b c d e f g h i j k l; do sed -i x /r/$u/.defenseclaw/config.yaml; done", []string{"sed -i x '/r/a/.defenseclaw/config.yaml'", "sed -i x '/r/l/.defenseclaw/config.yaml'"}, nil},
		{"login after eight words", "for u in a b c d e f g h $USER; do sed -i x /r/$u/.defenseclaw/config.yaml; done", []string{state}, nil},
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
		{"IFS declared", "export IFS=x; echo $USER | while read u; do sed -i x /r/$u/.defenseclaw/config.yaml; done", false},
		{"IFS emptied for the read", "echo $USER | while IFS= read -r u; do sed -i x /r/$u/.defenseclaw/config.yaml; done", true},
		{"IFS set for the read", "echo $USER | while IFS=: read -r u; do sed -i x /r/$u/.defenseclaw/config.yaml; done", true},
		{"IFS only spelled", "x=IFS; echo $USER | while read u; do sed -i x /r/$u/.defenseclaw/config.yaml; done", true},
		{"another prefix", "echo $USER | while PATH=/x read u; do sed -i x /r/$u/.defenseclaw/config.yaml; done", false},
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

// rel-1-0-6:GAP-0880, GAP-0885 review 1: the readings of a loop do not depend
// on the length of its list, on a function the action only declares, or on
// another loop that ends before the statement.
func TestSimpleCommandsLoopVariableNearForms(t *testing.T) {
	const state = "sed -i x '/r/home/.defenseclaw/config.yaml'"
	const write = "sed -i x /r/$u/.defenseclaw/config.yaml"
	words := func(count int, last string) string {
		list := ""
		for index := 0; index < count; index++ {
			list += "w" + string(rune('a'+index%26)) + string(rune('a'+index/26)) + " "
		}
		return list + last
	}
	for _, row := range []struct {
		name, command string
		reads         bool
	}{
		{"declared function after", "for u in $USER; do " + write + "; done; f() { :; }", true},
		{"declared function before", "f() { :; }; for u in $USER; do " + write + "; done", true},
		{"function called in the body", "f() { u=other; }; for u in $USER; do f; " + write + "; done", false},
		{"function called by the read loop body", "f() { u=other; }; echo $USER | while read u; do f; " + write + "; done", false},
		{"declared function with a read loop", "f() { :; }; echo $USER | while read u; do " + write + "; done", true},
		{"earlier binding survives an unrelated loop", "u=$USER; for a in x; do :; done; " + write + "; for u in x; do :; done", true},
		{"earlier binding survives an unrelated read loop", "u=$USER; echo x | while read a; do :; done; " + write, true},
		{"earlier binding ends with its own loop", "u=$USER; for u in x; do :; done; " + write, false},
		{"outer name survives an inner loop", "for u in $USER; do for a in x; do :; done; " + write + "; done", true},
		{"thirty words are read", "for u in " + words(29, "$USER") + "; do " + write + "; done", true},
	} {
		t.Run(row.name, func(t *testing.T) {
			input := Input{Tool: "Bash", Command: row.command, ActiveHome: "/r/home", CWD: "/r/home/proj"}
			read := false
			for _, simple := range SimpleCommands(input, Analyze(input)) {
				if simple.EvaluationFailure != "" {
					t.Fatalf("evaluation failure %q for %s", simple.EvaluationFailure, row.command)
				}
				read = read || simple.Text == state
			}
			if read != row.reads {
				t.Errorf("%s: reading of the state path = %v, want %v", row.command, read, row.reads)
			}
		})
	}
	t.Run("IFS ends the line", func(t *testing.T) {
		input := Input{Tool: "Bash", Command: "echo home | while IFS=e read -r u; do " + write + "; done", ActiveHome: "/r/home", CWD: "/r/home/proj"}
		var got []string
		for _, simple := range SimpleCommands(input, Analyze(input)) {
			got = append(got, simple.Text)
		}
		for _, want := range []string{state, "sed -i x '/r/hom/.defenseclaw/config.yaml'"} {
			if !slices.Contains(got, want) {
				t.Errorf("missing %q in %q", want, got)
			}
		}
	})
}

// rel-1-0-6:GAP-0880 review 1: a long list is read for the words that can name
// DefenseClaw state before the others, and never reports an evaluation limit:
// a long ordinary list is not an over-limit call.
func TestSimpleCommandsLoopLongListReadsStateNamesFirst(t *testing.T) {
	const state = "sed -i x '/r/home/.defenseclaw/config.yaml'"
	list := ""
	for index := 0; index < 100; index++ {
		list += "w" + string(rune('a'+index%26)) + string(rune('a'+index/26)) + " "
	}
	for _, row := range []struct {
		name, command string
		reads         bool
	}{
		{"login expansion last", "for u in " + list + "$USER; do sed -i x /r/$u/.defenseclaw/config.yaml; done", true},
		{"login literal last", "for u in " + list + "home; do sed -i x /r/$u/.defenseclaw/config.yaml; done", true},
		{"ordinary only", "for u in " + list + "; do sed -i x /r/$u/.defenseclaw/config.yaml; done", false},
		{"nested product", "for a in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16; do for b in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16; do echo $a $b; done; done", false},
		{"two loops in turn", "for a in 1 2 3 4 5 6 7 8 9 10 11 12; do echo $a; done; for u in $USER; do sed -i x /r/$u/.defenseclaw/config.yaml; done", true},
	} {
		t.Run(row.name, func(t *testing.T) {
			input := Input{Tool: "Bash", Command: row.command, ActiveHome: "/r/home", CWD: "/r/home/proj"}
			read := false
			for _, simple := range SimpleCommands(input, Analyze(input)) {
				if simple.EvaluationFailure != "" {
					t.Fatalf("evaluation failure %q for %.60s", simple.EvaluationFailure, row.command)
				}
				read = read || simple.Text == state
			}
			if read != row.reads {
				t.Errorf("%.60s: reading of the state path = %v, want %v", row.command, read, row.reads)
			}
		})
	}
}
