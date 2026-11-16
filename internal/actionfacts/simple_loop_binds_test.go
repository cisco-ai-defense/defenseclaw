// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
	"mvdan.cc/sh/v3/syntax"
)

// rel-1-0-6:GAP-0880: a for variable other than USER and LOGNAME is read once
// for each word of its list that the walk can read, with the value rules of
// an assignment. The reading of the statement that leaves it unread stays.
func TestSimpleCommandsReadLoopVariableWords(t *testing.T) {
	// hereStringRows are the rows whose read of a here-string word binds the
	// variable for certain.
	hereStringRows := map[string]bool{"read from a here-string": true, "read with -r": true,
		"read declared as a function after the loop": true, "read of a here-string outside a loop": true}
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
		{"every plain word is read", "for u in a b c d e f g h i j k l; do sed -i x /r/$u/.defenseclaw/config.yaml; done", []string{"sed -i x '/r/a/.defenseclaw/config.yaml'", "sed -i x '/r/e/.defenseclaw/config.yaml'", "sed -i x '/r/l/.defenseclaw/config.yaml'"}, nil},
		{"login after eight words", "for u in a b c d e f g h $USER; do sed -i x /r/$u/.defenseclaw/config.yaml; done", []string{state}, nil},
		{"body binds the name", "for u in other; do u=home; sed -i x /r/$u/.defenseclaw/config.yaml; done", []string{state}, []string{other}},
		{"read in the body", "for u in other; do read u; sed -i x /r/$u/.defenseclaw/config.yaml; done", nil, []string{other}},
		{"write before the binding", "for u in home; do sed -i x /r/$u/.defenseclaw/config.yaml; u=other; done", []string{state}, nil},
		{"write before an export", "for u in home; do sed -i x /r/$u/.defenseclaw/config.yaml; export u=other; done", []string{state}, nil},
		{"write before a read", "for u in home; do sed -i x /r/$u/.defenseclaw/config.yaml; read u; done", []string{state}, nil},
		{"write before a called function", "f() { u=other; }; for u in home; do sed -i x /r/$u/.defenseclaw/config.yaml; f; done", []string{state}, nil},
		{"function declared in the body is not a binding", "for u in home; do f() { u=other; }; sed -i x /r/$u/.defenseclaw/config.yaml; done", []string{state}, nil},
		{"prefix assignment is not a binding", "for u in home; do u=other true; sed -i x /r/$u/.defenseclaw/config.yaml; done", []string{state}, nil},
		// A branch may not run: the word of the loop stays read next to the bound one.
		{"write after a binding in a branch", "for u in other; do if test -f /x; then u=home; fi; sed -i x /r/$u/.defenseclaw/config.yaml; done", []string{state, other}, nil},
		{"write after a binding in one branch of two", "for u in other; do if test -f /x; then u=home; else :; fi; sed -i x /r/$u/.defenseclaw/config.yaml; done", []string{state, other}, nil},
		{"write after a binding in an arm without a default", "for u in other; do case x in y) u=home;; z) u=home;; esac; sed -i x /r/$u/.defenseclaw/config.yaml; done", []string{state, other}, nil},
		// Code that certainly runs ends the word of the loop (review 4).
		{"write after a binding in an if that is true", "for u in other; do if true; then u=home; fi; sed -i x /r/$u/.defenseclaw/config.yaml; done", []string{state}, []string{other}},
		{"write after a binding in an if with a colon", "for u in other; do if :; then u=home; fi; sed -i x /r/$u/.defenseclaw/config.yaml; done", []string{state}, []string{other}},
		{"write after a binding in the else of a false if", "for u in other; do if false; then :; else u=home; fi; sed -i x /r/$u/.defenseclaw/config.yaml; done", []string{state}, []string{other}},
		{"write after a binding in both branches", "for u in other; do if test -f /x; then u=home; else u=home; fi; sed -i x /r/$u/.defenseclaw/config.yaml; done", []string{state}, []string{other}},
		{"write after a binding in every arm", "for u in other; do case x in y) u=home;; *) u=home;; esac; sed -i x /r/$u/.defenseclaw/config.yaml; done", []string{state}, []string{other}},
		{"write after a binding behind a true and", "for u in other; do true && u=home; sed -i x /r/$u/.defenseclaw/config.yaml; done", []string{state}, []string{other}},
		{"write after a binding behind a negated false and", "for u in other; do ! false && u=home; sed -i x /r/$u/.defenseclaw/config.yaml; done", []string{state}, []string{other}},
		{"write after a binding behind a false or", "for u in other; do false || u=home; sed -i x /r/$u/.defenseclaw/config.yaml; done", []string{state}, []string{other}},
		{"write after a printf -v", "for u in other; do printf -v u home; sed -i x /r/$u/.defenseclaw/config.yaml; done", nil, []string{other}},
		{"write in the same if after its binding", "for u in other; do if true; then u=home; sed -i x /r/$u/.defenseclaw/config.yaml; fi; done", []string{state}, []string{other}},
		{"write on the right of a binding and", "for u in other; do u=home && sed -i x /r/$u/.defenseclaw/config.yaml; done", []string{state}, []string{other}},
		// A function the action declares replaces the builtin of its name.
		{"read shadowed by a function", "read() { :; }; for u in home; do read u; sed -i x /r/$u/.defenseclaw/config.yaml; done", []string{state}, nil},
		{"printf shadowed by a function", "printf() { :; }; for u in home; do printf -v u other; sed -i x /r/$u/.defenseclaw/config.yaml; done", []string{state}, nil},
		{"true shadowed by a function", "true() { return 1; }; for u in home; do true && u=other; sed -i x /r/$u/.defenseclaw/config.yaml; done", []string{state}, nil},
		{"read declared as a function after the loop is still the builtin", "for u in home; do read u; sed -i x /r/$u/.defenseclaw/config.yaml; done; read() { :; }", nil, []string{state}},
		{"write after a binding that cannot run", "for u in other; do if false; then u=home; fi; sed -i x /r/$u/.defenseclaw/config.yaml; done", []string{other}, nil},
		{"write after a binding behind a failed and", "for u in other; do false && u=home; sed -i x /r/$u/.defenseclaw/config.yaml; done", []string{other}, nil},
		{"write after a binding behind a skipped or", "for u in other; do true || u=home; sed -i x /r/$u/.defenseclaw/config.yaml; done", []string{other}, nil},
		{"write after a binding in a case arm", "for u in other; do case x in y) u=home;; esac; sed -i x /r/$u/.defenseclaw/config.yaml; done", []string{other}, nil},
		{"write after a binding in a subshell", "for u in other; do (u=home); sed -i x /r/$u/.defenseclaw/config.yaml; done", []string{other}, nil},
		{"write after a binding behind an unknown and", "for u in other; do test -f /x && u=home; sed -i x /r/$u/.defenseclaw/config.yaml; done", []string{other}, nil},
		{"write after a binding in a pipeline stage", "for u in other; do u=home | cat; sed -i x /r/$u/.defenseclaw/config.yaml; done", []string{other}, nil},
		{"write after a read in a branch", "for u in other; do if false; then read u; fi; sed -i x /r/$u/.defenseclaw/config.yaml; done", []string{other}, nil},
		{"write after arithmetic on another name", "for u in other; do ((i++)); sed -i x /r/$u/.defenseclaw/config.yaml; done", []string{other}, nil},
		{"write after an unconditional binding in a block", "for u in other; do { u=home; }; sed -i x /r/$u/.defenseclaw/config.yaml; done", []string{state}, []string{other}},
		{"write after the left side of an and", "for u in other; do u=home && true; sed -i x /r/$u/.defenseclaw/config.yaml; done", []string{state}, []string{other}},
		{"write after a binding in the condition of an if", "for u in other; do if read u; then :; fi; sed -i x /r/$u/.defenseclaw/config.yaml; done", nil, []string{other}},
		{"write after a read with a prompt option", "for u in other; do read -p u v; sed -i x /r/$u/.defenseclaw/config.yaml; done", []string{other}, nil},
		{"write in an inner loop that binds", "for u in home; do while true; do sed -i x /r/$u/.defenseclaw/config.yaml; u=other; done; done", []string{state}, nil},
		// A binding that does not run leaves the word (the call fails first), one that runs ends it,
		// and a function replaces a builtin only for the calls that come after its declaration (review 5).
		{"read whose input redirection can fail", "for u in home; do read u < /nonexistent/in; sed -i x /r/$u/.defenseclaw/config.yaml; done", []string{state}, nil},
		{"printf -v whose output redirection can fail", "for u in home; do printf -v u other > /nonexistent/out; sed -i x /r/$u/.defenseclaw/config.yaml; done", []string{state}, nil},
		{"printf -v without a format", "for u in home; do printf -v u; sed -i x /r/$u/.defenseclaw/config.yaml; done", []string{state}, nil},
		{"read with a timeout", "for u in home; do read -t 1 u; sed -i x /r/$u/.defenseclaw/config.yaml; done", []string{state}, nil},
		{"read with a delimiter", "for u in home; do read -d x u; sed -i x /r/$u/.defenseclaw/config.yaml; done", []string{state}, nil},
		{"local outside a function", "for u in home; do local u=other; sed -i x /r/$u/.defenseclaw/config.yaml; done", []string{state}, nil},
		{"read from a here-string", "for u in home; do read u <<< other; sed -i x /r/$u/.defenseclaw/config.yaml; done", []string{other}, []string{state}},
		{"read with a redirect to /dev/null", "for u in home; do read u < /dev/null; sed -i x /r/$u/.defenseclaw/config.yaml; done", nil, []string{state}},
		{"read with -r", "for u in home; do read -r u <<< other; sed -i x /r/$u/.defenseclaw/config.yaml; done", []string{other}, []string{state}},
		{"printf -v with a format", "for u in home; do printf -v u %s other; sed -i x /r/$u/.defenseclaw/config.yaml; done", nil, []string{state}},
		{"assignment whose redirection fails still binds", "for u in home; do u=other < /nonexistent/in; sed -i x /r/$u/.defenseclaw/config.yaml; done", nil, []string{state}},
		{"local in a function", "f() { for u in home; do local u=other; sed -i x /r/$u/.defenseclaw/config.yaml; done; }; f", nil, []string{state}},
		{"read declared as a function after the loop", "for u in home; do read u <<< other; sed -i x /r/$u/.defenseclaw/config.yaml; done; read() { :; }", []string{other}, []string{state}},
		{"printf declared as a function after the loop", "for u in home; do printf -v u other; sed -i x /r/$u/.defenseclaw/config.yaml; done; printf() { :; }", nil, []string{state}},
		{"true declared as a function after the loop", "for u in home; do if true; then u=other; fi; sed -i x /r/$u/.defenseclaw/config.yaml; done; true() { :; }", nil, []string{state}},
		{"false declared as a function after the loop", "for u in home; do false || u=other; sed -i x /r/$u/.defenseclaw/config.yaml; done; false() { :; }", nil, []string{state}},
		{"read declared as a function in the loop after the call", "for u in home; do read u <<< other; sed -i x /r/$u/.defenseclaw/config.yaml; read() { :; }; done", []string{state}, nil},
		{"read declared as a function in a loop that runs again", "for i in 1 2; do for u in home; do read u <<< other; sed -i x /r/$u/.defenseclaw/config.yaml; done; read() { :; }; done", []string{state}, nil},
		{"read declared as a function before the loop", "read() { :; }; for u in home; do read u <<< other; sed -i x /r/$u/.defenseclaw/config.yaml; done", []string{state}, nil},
		{"read in a function declared before a later declaration", "f() { for u in home; do read u <<< other; sed -i x /r/$u/.defenseclaw/config.yaml; done; }; read() { :; }; f", []string{state}, nil},
		// read of a here-string gives the name its word (the default IFS, the builtin).
		{"read of a here-string outside a loop", "read u <<< other; sed -i x /r/$u/.defenseclaw/config.yaml", []string{other}, nil},
		{"read of a here-string when the action spells IFS", "IFS=x; read u <<< other; sed -i x /r/$u/.defenseclaw/config.yaml", nil, []string{other}},
		{"read of a here-string shadowed by a function", "read() { :; }; read u <<< other; sed -i x /r/$u/.defenseclaw/config.yaml", nil, []string{other}},
		{"select reads the words of its list", "select u in $USER; do sed -i x /r/$u/.defenseclaw/config.yaml; break; done", []string{state}, nil},
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
					// a statement whose name the body binds is an ordinary one, as
					// is the one after a read of a here-string word.
					ordinary := simple.Text == state && strings.Contains(row.command, "u=home") || hereStringRows[row.name]
					if simple.Text == want && simple.LoginGuess == ordinary {
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
		{"here-string", "while read u; do sed -i x /r/$u/.defenseclaw/config.yaml; done <<< $USER", true},
		{"quoted here-string", "while read -r u; do sed -i x /r/$u/.defenseclaw/config.yaml; done <<< \"$USER\"", true},
		{"literal here-string", "while read u; do sed -i x /r/$u/.defenseclaw/config.yaml; done <<< home", true},
		{"here-string with two words", "while read u; do sed -i x /r/$u/.defenseclaw/config.yaml; done <<< \"$USER other\"", false},
		{"here-string after a pipe stage", "echo x | while read u; do sed -i x /r/$u/.defenseclaw/config.yaml; done <<< $USER", true},
		{"unreadable input", "ls | while read u; do sed -i x /r/$u/.defenseclaw/config.yaml; done", false},
		{"changed IFS", "IFS=x; echo $USER | while read u; do sed -i x /r/$u/.defenseclaw/config.yaml; done", true},
		{"IFS declared", "export IFS=x; echo $USER | while read u; do sed -i x /r/$u/.defenseclaw/config.yaml; done", true},
		{"IFS emptied for the read", "echo $USER | while IFS= read -r u; do sed -i x /r/$u/.defenseclaw/config.yaml; done", true},
		{"IFS set for the read", "echo $USER | while IFS=: read -r u; do sed -i x /r/$u/.defenseclaw/config.yaml; done", true},
		{"IFS only spelled", "x=IFS; echo $USER | while read u; do sed -i x /r/$u/.defenseclaw/config.yaml; done", true},
		{"IFS bound after the loop", "echo $USER | while read u; do sed -i x /r/$u/.defenseclaw/config.yaml; done; IFS=x", true},
		{"IFS bound in the body", "echo $USER | while read u; do sed -i x /r/$u/.defenseclaw/config.yaml; IFS=x; done", true},
		{"IFS bound in a declared function", "f() { IFS=x; }; echo $USER | while read u; do sed -i x /r/$u/.defenseclaw/config.yaml; done", true},
		{"IFS bound in a called function", "f() { IFS=x; }; f; echo $USER | while read u; do sed -i x /r/$u/.defenseclaw/config.yaml; done", true},
		{"IFS bound after the loop that runs again", "while true; do echo $USER | while read u; do sed -i x /r/$u/.defenseclaw/config.yaml; done; IFS=x; done", true},
		{"IFS assigned in a branch that does not run", "if false; then IFS=x; fi; echo $USER | while read u; do sed -i x /r/$u/.defenseclaw/config.yaml; done", true},
		{"IFS bound before a read with its own", "IFS=x; echo $USER | while IFS= read -r u; do sed -i x /r/$u/.defenseclaw/config.yaml; done", true},
		{"another prefix", "echo $USER | while PATH=/x read u; do sed -i x /r/$u/.defenseclaw/config.yaml; done", false},
		{"body binds the name", "echo $USER | while read u; do read u; sed -i x /r/$u/.defenseclaw/config.yaml; done", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			input := Input{Tool: "Bash", Command: row.command, ActiveHome: "/r/home", CWD: "/r/home/proj"}
			read := false
			for _, simple := range SimpleCommands(input, Analyze(input)) {
				read = read || strings.HasPrefix(simple.Text, state)
			}
			if read != row.reads {
				t.Errorf("%s: reading of the state path = %v, want %v", row.command, read, row.reads)
			}
		})
	}
}

// rel-1-0-6:GAP-0880, GAP-0885 review 4: a read loop reads with the IFS that
// reaches it: the value the walk holds where the loop starts (also one a
// known variable gave it), with the values an enclosing loop that runs again or
// a function it calls assigns. Code after the loop, in its body or in a
// function that is not called before it cannot reach the read.
func TestSimpleCommandsReadLoopIFSReachingTheRead(t *testing.T) {
	const write = "sed -i x /r/$d/.defenseclaw/config.yaml"
	const stripped = "sed -i x '/r/home/.defenseclaw/config.yaml'"
	const kept = "sed -i x '/r/homex/.defenseclaw/config.yaml'"
	const read = "echo homex | while read -r d; do " + write + "; done"
	for _, row := range []struct {
		name, command          string
		wantStripped, wantKept bool
	}{
		{"default", read, false, true},
		{"assigned before", "IFS=x; " + read, true, false},
		{"known variable", "sep=x; IFS=$sep; " + read, true, false},
		{"known variable declared", "sep=x; export IFS=$sep; " + read, true, false},
		{"unknown variable", "IFS=$(cat /x); " + read, false, true},
		{"assigned after the loop", read + "; IFS=x", false, true},
		{"assigned in the body after the write", "echo homex | while read -r d; do " + write + "; IFS=x; done", false, true},
		{"assigned in a function declared after", read + "; f() { IFS=x; }", false, true},
		{"assigned in a function declared before", "f() { IFS=x; }; " + read, false, true},
		{"assigned by a function called before", "f() { IFS=x; }; f; " + read, true, false},
		{"assigned in a branch", "if test -f /x; then IFS=x; fi; " + read, true, true},
		{"emptied for the read", "IFS=y; echo homex | while IFS= read -r d; do " + write + "; done", false, true},
		{"set for the read", "echo homex | while IFS=x read -r d; do " + write + "; done", true, false},
		{"loop that runs again", "while test -f /x; do " + read + "; IFS=x; done", true, true},
		{"for loop over one word", "for i in 1; do " + read + "; IFS=x; done", false, true},
		{"for loop over two words", "for i in 1 2; do " + read + "; IFS=x; done", true, true},
		{"function called before the assignment", "f() { " + read + "; }; f; IFS=x", false, true},
		{"function called after the assignment", "f() { " + read + "; }; IFS=x; f", true, false},
		{"function called by a loop", "f() { " + read + "; }; for i in 1 2; do f; IFS=x; done", true, true},
		// A function reaches the read only through a call in the loop (review 5).
		{"function declared before an outer loop, not called", "f() { IFS=x; }; for i in 1 2; do " + read + "; done", false, true},
		{"function declared after an outer loop", "for i in 1 2; do " + read + "; done; f() { IFS=x; }", false, true},
		{"function declared in the loop, not called", "for i in 1 2; do f() { IFS=x; }; " + read + "; done", false, true},
		{"function called in the outer loop", "f() { IFS=x; }; for i in 1 2; do " + read + "; f; done", true, true},
		{"function called through another function", "f() { IFS=x; }; g() { f; }; for i in 1 2; do " + read + "; g; done", true, true},
		{"local IFS of a called function", "f() { local IFS=x; }; for i in 1 2; do " + read + "; f; done", false, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			input := Input{Tool: "Bash", Command: row.command, ActiveHome: "/r/home", CWD: "/r/home/proj"}
			var got []string
			for _, simple := range SimpleCommands(input, Analyze(input)) {
				if simple.EvaluationFailure != "" {
					t.Fatalf("evaluation failure %q for %s", simple.EvaluationFailure, row.command)
				}
				got = append(got, simple.Text)
			}
			if has := slices.Contains(got, stripped); has != row.wantStripped {
				t.Errorf("%s: reads the delimiter-stripped word = %v, want %v (%q)", row.command, has, row.wantStripped, got)
			}
			if has := slices.Contains(got, kept); has != row.wantKept {
				t.Errorf("%s: reads the whole word = %v, want %v (%q)", row.command, has, row.wantKept, got)
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
		{"binding after the write", "for u in $USER; do " + write + "; u=other; done", true},
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
	// read drops one trailing delimiter of its IFS, and only when it is the one
	// delimiter of the word (the shell reads aliasdir as aliasdi with IFS=r).
	for _, row := range []struct {
		name, word, ifs, want string
	}{
		{"one trailing delimiter", "home", "e", "hom"},
		{"a second delimiter keeps the word", "eve", "e", "eve"},
		{"inner delimiter only", "homes", "e", "homes"},
		{"no delimiter", "home", ":", "home"},
		{"no IFS of its own", "home", "", "home"},
		{"a multibyte delimiter is one character", "homeé", "é", "home"},
		{"a multibyte delimiter keeps the word with another", "éhomeé", "é", "éhomeé"},
	} {
		t.Run(row.name, func(t *testing.T) {
			prefix := ""
			if row.ifs != "" {
				prefix = "IFS=" + row.ifs + " "
			}
			input := Input{Tool: "Bash", Command: "echo " + row.word + " | while " + prefix + "read -r u; do " + write + "; done", ActiveHome: "/r/home", CWD: "/r/home/proj"}
			var got []string
			for _, simple := range SimpleCommands(input, Analyze(input)) {
				got = append(got, simple.Text)
			}
			if want := "sed -i x '/r/" + row.want + "/.defenseclaw/config.yaml'"; !slices.Contains(got, want) {
				t.Errorf("missing %q in %q", want, got)
			}
			if row.want != row.word {
				if unwanted := "sed -i x '/r/" + row.word + "/.defenseclaw/config.yaml'"; slices.Contains(got, unwanted) {
					t.Errorf("unexpected %q in %q", unwanted, got)
				}
			}
		})
	}
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
	paths := ""
	for index := 0; index < 60; index++ {
		paths += "x" + string(rune('a'+index%26)) + string(rune('a'+index/26)) + ".txt "
	}
	for _, row := range []struct {
		name, command string
		reads         bool
	}{
		{"login after sixty path words", "for u in " + paths + "$USER; do sed -i x /r/$u/.defenseclaw/config.yaml; done", true},
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

// rel-1-0-6:GAP-0880 review 2: the plain words of a list that share one state
// (simplePlaceholderToken) read the commands that each word read alone does,
// and a body that does more with the variable than name a file operand reads
// each word alone.
func TestSimpleCommandsPlainWordsShareOneState(t *testing.T) {
	commands := []string{
		"for u in alice bob carol; do cp a.txt ../$u/x:y; done",
		"for u in alice bob carol $USER; do cp a.txt ../$u/x:y; done",
		"for u in alice bob a.b; do sed -i x /r/$u/.defenseclaw/config.yaml; done",
		"for u in alice bob; do d=$u/x; cp a.txt /r/$d; printf x > /r/$d/y; done",
		"for u in alice bob; do cp a.txt /r/$u/x && mv /r/$u/x /r/$u/y; done",
		"for u in alice bob; do cd /r/$u; cp a.txt b.txt; done",
		"for u in alice bob; do cd /r; cp a.txt $u/x; done",
		"for u in alice bob; do $u -c x; done",
		"for u in sh bash; do $u -c 'echo x > /r/home/.defenseclaw/y'; done",
		"for u in alice bob; do bash -c 'cp a /r/$u/x'; done",
		"for u in alice bob; do cp a.txt $(echo /r/$u)/x; done",
		"for u in alice bob; do if true; then cp a.txt /r/$u/x; fi; done",
		"for u in alice bob; do cp a.txt /r/${u}/x /r/${u%b}/y; done",
		"for u in alice bob; do u=other; cp a.txt /r/$u/x; done",
		"for u in alice bob; do cp a.txt /r/$u/x; u=other; cp a.txt /r/$u/y; done",
		"for a in x y; do for b in alice bob; do cp a.txt /r/$a/$b; done; done",
		"for u in a-b c_d 1e alice; do cp a.txt /r/$u/x; done",
		"cd /r/home; for u in alice bob; do cp a.txt $u/x; done; cp a.txt z",
	}
	read := func(command string) map[SimpleCommand]bool {
		input := Input{Tool: "Bash", Command: command, ActiveHome: "/r/home", CWD: "/r/home/proj"}
		got := make(map[SimpleCommand]bool)
		for _, simple := range SimpleCommands(input, Analyze(input)) {
			got[simple] = true
		}
		return got
	}
	defer func(was bool) { simplePlaceholderForks = was }(simplePlaceholderForks)
	ordered := func(command string) []SimpleCommand {
		input := Input{Tool: "Bash", Command: command, ActiveHome: "/r/home", CWD: "/r/home/proj"}
		return SimpleCommands(input, Analyze(input))
	}
	for _, command := range commands {
		simplePlaceholderForks = true
		// Two walks of one action write the commands in one order: the
		// gateway matches them by position.
		if first, second := ordered(command), ordered(command); !slices.Equal(first, second) {
			t.Errorf("%s: two walks differ:\n%+v\n%+v", command, first, second)
		}
		shared := read(command)
		simplePlaceholderForks = false
		alone := read(command)
		for simple := range shared {
			if !alone[simple] {
				t.Errorf("%s: shared state reads %+v that each word alone does not", command, simple)
			}
		}
		for simple := range alone {
			if !shared[simple] {
				t.Errorf("%s: each word alone reads %+v that the shared state does not", command, simple)
			}
		}
	}
	simplePlaceholderForks = true
	for _, row := range []struct {
		body   string
		shared bool
	}{
		{"cp a.txt /r/$u/x; sed -i x /r/$u/y > /r/$u/z", true},
		{"d=$u/x; printf x | tee /r/$d", true},
		{"$u -c x", false},
		{"cd /r/$u", false},
		{"bash -c 'cp a /r/$u/x'", false},
		{"cp a $(echo $u)", false},
		{"if true; then cp a /r/$u; fi", false},
		{"cp a /r/${u%b}", false},
		{"find /r/$u -exec rm {} +", false},
	} {
		file, ok := shellparse.Parse("for u in a b; do " + row.body + "; done")
		if !ok {
			t.Fatalf("parse %q", row.body)
		}
		loop := file.Stmts[0].Cmd.(*syntax.ForClause)
		if shared := simplePlaceholderToken(loop.Do, "u", "") != ""; shared != row.shared {
			t.Errorf("%s: shared state = %v, want %v", row.body, shared, row.shared)
		}
	}
}

// rel-1-0-6:GAP-0880 review 3: a construct only Bash has (select) is rejected
// by the POSIX reader of the call, yet each command of it is read as any
// other, from the command the tool arguments carry.
func TestSimpleCommandsReadBashOnlyLoopFromArguments(t *testing.T) {
	const state = "sed -i x '/r/home/.defenseclaw/config.yaml'"
	for _, row := range []struct {
		name, command string
		reads         bool
	}{
		{"select", "select u in $USER; do sed -i x /r/$u/.defenseclaw/config.yaml; break; done", true},
		{"select ordinary", "select u in alice; do sed -i x /r/$u/notes.txt; break; done", false},
		{"for", "for u in $USER; do sed -i x /r/$u/.defenseclaw/config.yaml; break; done", true},
	} {
		t.Run(row.name, func(t *testing.T) {
			args, err := json.Marshal(map[string]string{"command": row.command})
			if err != nil {
				t.Fatal(err)
			}
			input := Input{Tool: "Bash", Args: args, ActiveHome: "/r/home", CWD: "/r/home/proj"}
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

// A call the POSIX reader rejects and the shell parse cannot read in full (here
// past the state bound) keeps the judgment it had: no evaluation failure
// reaches the gateway from the added readings.
func TestSimpleCommandsBashOnlyCallPastTheBoundAddsNoFailure(t *testing.T) {
	var command strings.Builder
	for index := 1; index <= 9; index++ {
		fmt.Fprintf(&command, "if [ -n \"$A%d\" ]; then a%d=1; fi; ", index, index)
	}
	command.WriteString("read -r f <<< out.txt; echo m >> \"$f\"")
	args, err := json.Marshal(map[string]string{"command": command.String()})
	if err != nil {
		t.Fatal(err)
	}
	input := Input{Tool: "Bash", Args: args, ActiveHome: "/r/home", CWD: "/r/home/proj"}
	if got := SimpleCommands(input, Analyze(input)); len(got) != 0 {
		t.Errorf("SimpleCommands = %v, want none", got)
	}
}
