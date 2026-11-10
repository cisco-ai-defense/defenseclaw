// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"slices"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

// rel-1-0-6:GAP-0880, GAP-0885 review 9: a read of a here-string in a function
// binds its word in the calls that run the builtin with the default IFS, and
// only in those. The state of one call does not decide for another: a function
// declaration or an IFS that comes between two calls changes the later call
// alone.
func TestSimpleCommandsHereStringReadBindsInTheCallsThatRunTheBuiltin(t *testing.T) {
	const alice = "sed -i x \x27/r/alice/.defenseclaw/config.yaml\x27"
	const bob = "sed -i x \x27/r/bob/.defenseclaw/config.yaml\x27"
	const body = "f() { read d <<< alice; sed -i x /r/$d/.defenseclaw/config.yaml; }; "
	for _, row := range []struct {
		name, command string
		straight      bool
		alice, bob    bool
	}{
		{"one call", "d=bob; " + body + "f", true, true, false},
		{"top level read", "d=bob; read d <<< alice; sed -i x /r/$d/.defenseclaw/config.yaml", true, true, false},
		{"second call after a replacing function", "d=bob; " + body + "f; read() { :; }; d=bob; f", true, true, true},
		{"second call through a caller", "d=bob; g() { f; }; " + body + "g; read() { :; }; d=bob; g", true, true, true},
		{"second call after an IFS", "d=bob; " + body + "f; IFS=x; d=bob; f", true, true, true},
		{"only call after a replacing function", "d=bob; " + body + "read() { :; }; f", true, false, true},
		{"replacing function after the only call", "d=bob; " + body + "f; read() { :; }", true, true, false},
		{"second call in a branch that does not run", "d=bob; " + body + "f; read() { :; }; d=bob; if false; then f; fi", true, true, false},
		// The reading of a whole script counts a function named read wherever
		// it is declared: the read is not followed (the hook client reads the
		// straight-line reading too).
		{"whole script, replacing function after a call", "d=bob; " + body + "f; read() { :; }; d=bob; f", false, false, true},
		{"whole script, one call", "d=bob; " + body + "f", false, true, false},
		{"whole script, read at the top level", "d=bob; read d <<< alice; sed -i x /r/$d/.defenseclaw/config.yaml", false, true, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			got := simpleTextsOf(t, row.command, row.straight)
			if has := slices.Contains(got, alice); has != row.alice {
				t.Errorf("reading of %q: word of the read = %v, want %v (%q)", row.command, has, row.alice, got)
			}
			if has := slices.Contains(got, bob); has != row.bob {
				t.Errorf("reading of %q: word before the read = %v, want %v (%q)", row.command, has, row.bob, got)
			}
		})
	}
}

// ReadBindsHereString tells the calls of a function that bind from those that
// do not, so a caller that rewrites the read once does not judge them all by
// one.
func TestReadBindsHereStringSaysWhetherEveryRunBinds(t *testing.T) {
	const body = "f() { read d <<< alice; }; "
	for _, row := range []struct {
		name, command string
		all, some     bool
	}{
		{"top level", "read d <<< alice", true, true},
		{"one call", body + "f", true, true},
		{"every call before a replacing function", body + "f; f; read() { :; }", true, true},
		{"calls before and after a replacing function", body + "f; read() { :; }; f", false, true},
		{"calls before and after an IFS", body + "f; IFS=x; f", false, true},
		{"every call after a replacing function", body + "read() { :; }; f; f", false, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(row.command), "")
			if err != nil {
				t.Fatal(err)
			}
			binds := ReadBindsHereString(file, true)
			var read *syntax.CallExpr
			syntax.Walk(file, func(node syntax.Node) bool {
				if call, ok := node.(*syntax.CallExpr); ok && len(call.Args) > 0 && call.Args[0].Lit() == "read" && len(call.Args) == 2 {
					read = call
				}
				return true
			})
			if read == nil {
				t.Fatalf("no read in %q", row.command)
			}
			if all, some := binds(read); all != row.all || some != row.some {
				t.Errorf("ReadBindsHereString(%q) = (%v, %v), want (%v, %v)", row.command, all, some, row.all, row.some)
			}
		})
	}
}

// rel-1-0-6:GAP-0880, GAP-0885 review 9: declare reads its options up to the
// first name, so a print flag after an assignment is a name and the assignment
// of IFS stands; in front of it the flag prints and nothing is assigned.
func TestSimpleCommandsDeclareOptionAfterAnIFSAssignmentStillAssigns(t *testing.T) {
	const stripped = "sed -i x \x27/r/home/.defenseclaw/config.yaml\x27"
	const kept = "sed -i x \x27/r/homex/.defenseclaw/config.yaml\x27"
	const loop = "; echo homex | while read -r d; do sed -i x /r/$d/.defenseclaw/config.yaml; done"
	for _, row := range []struct {
		name, command  string
		stripped, kept bool
	}{
		{"assignment", "declare IFS=x" + loop, true, false},
		{"assignment then print flag", "declare IFS=x -p" + loop, true, false},
		{"typeset assignment then print flag", "typeset IFS=x -p" + loop, true, false},
		{"assignment then function flag", "declare IFS=x -f" + loop, true, false},
		{"export flag then assignment", "declare -x IFS=x" + loop, true, false},
		{"print flag then assignment", "declare -p IFS=x" + loop, false, true},
		{"no assignment", "declare -p IFS" + loop, false, true},
	} {
		for _, straight := range []bool{true, false} {
			t.Run(row.name, func(t *testing.T) {
				got := simpleTextsOf(t, row.command, straight)
				if has := slices.Contains(got, stripped); has != row.stripped {
					t.Errorf("straight=%v reading of %q: delimiter-stripped word = %v, want %v (%q)", straight, row.command, has, row.stripped, got)
				}
				if has := slices.Contains(got, kept); has != row.kept {
					t.Errorf("straight=%v reading of %q: whole word = %v, want %v (%q)", straight, row.command, has, row.kept, got)
				}
			})
		}
	}
}

// A read in a for loop of a function that is called before and after a
// function named read binds the loop variable in the first call only.
func TestSimpleCommandsStraightLineLoopReadBindsInTheCallsThatRunTheBuiltin(t *testing.T) {
	const state = "sed -i x \x27/r/home/.defenseclaw/config.yaml\x27"
	const other = "sed -i x \x27/r/other/.defenseclaw/config.yaml\x27"
	const body = "f() { for u in home; do read u <<< other; sed -i x /r/$u/.defenseclaw/config.yaml; done; }; "
	for _, row := range []struct {
		name, command string
		state, other  bool
	}{
		{"declared before one call of the function and after another", body + "f; read() { :; }; f", true, true},
		{"declared before the only call", body + "read() { :; }; f", true, false},
		{"declared after the only call", body + "f; read() { :; }", false, true},
		{"not declared", body + "f; f", false, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			got := simpleTextsOf(t, row.command, true)
			if has := slices.Contains(got, state); has != row.state {
				t.Errorf("reading of %q: loop word = %v, want %v (%q)", row.command, has, row.state, got)
			}
			if has := slices.Contains(got, other); has != row.other {
				t.Errorf("reading of %q: word read = %v, want %v (%q)", row.command, has, row.other, got)
			}
		})
	}
}
