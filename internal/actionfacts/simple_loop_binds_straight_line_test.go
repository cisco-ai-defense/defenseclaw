// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"slices"
	"testing"
)

// simpleTextsOf returns the text of each simple command of command, with the
// straight-line reading on or off.
func simpleTextsOf(t *testing.T, command string, straight bool) []string {
	t.Helper()
	input := Input{Tool: "Bash", Command: command, ActiveHome: "/r/home", CWD: "/r/home/proj", LoopBindsStraightLine: straight}
	var got []string
	for _, simple := range SimpleCommands(input, Analyze(input)) {
		if simple.EvaluationFailure != "" {
			t.Fatalf("evaluation failure %q for %s", simple.EvaluationFailure, command)
		}
		got = append(got, simple.Text)
	}
	return got
}

// rel-1-0-6:GAP-0880, GAP-0885 review 6: in the straight-line reading (the
// default and permissive tiers) a function named read replaces the builtin only
// when a top-level statement before the call declares it; the reading
// without it (the strict tier, the hook client) also counts a declaration in a
// function body, a branch or a loop, which the shell may never run.
func TestSimpleCommandsStraightLineReadDeclarationReachesOnlyFromTopLevel(t *testing.T) {
	const state = "sed -i x \x27/r/home/.defenseclaw/config.yaml\x27"
	const other = "sed -i x \x27/r/other/.defenseclaw/config.yaml\x27"
	const loop = "for u in home; do read u <<< other; sed -i x /r/$u/.defenseclaw/config.yaml; done"
	for _, row := range []struct {
		name, command string
		// straightReads and fullReads name the reading of the write: the
		// state of the loop word (state) or the word read (other).
		straightReads, fullReads string
	}{
		{"declared before the loop", "read() { :; }; " + loop, state, state},
		{"declared in a function the action calls before the loop", "f() { read() { :; }; }; f; " + loop, other, state},
		{"declared in a function the action never calls", "f() { read() { :; }; }; " + loop, other, state},
		{"declared in a branch that does not run", "if false; then read() { :; }; fi; " + loop, other, state},
		{"declared in a branch that runs", "if true; then read() { :; }; fi; " + loop, other, state},
		{"declared after the function that runs the loop", "f() { " + loop + "; }; f; read() { :; }", other, state},
		{"declared at the top level before the call of the function that runs the loop", "f() { " + loop + "; }; read() { :; }; f", state, state},
		{"declared before one call of the function and after another", "f() { " + loop + "; }; f; read() { :; }; f", state, state},
		{"declared before the call of a function that calls the one that runs the loop", "g() { f; }; f() { " + loop + "; }; read() { :; }; g", state, state},
		{"declared after the call of a function that calls the one that runs the loop", "g() { f; }; f() { " + loop + "; }; g; read() { :; }", other, state},
		{"declared after the loop", loop + "; read() { :; }", other, other},
		{"declared in the loop, after the call", "for i in 1 2; do " + loop + "; read() { :; }; done", other, state},
		{"not declared", loop, other, other},
	} {
		t.Run(row.name, func(t *testing.T) {
			for _, mode := range []struct {
				name     string
				straight bool
				reads    string
			}{{"straight-line", true, row.straightReads}, {"full", false, row.fullReads}} {
				got := simpleTextsOf(t, row.command, mode.straight)
				absent := state
				if mode.reads == state {
					absent = other
				}
				if !slices.Contains(got, mode.reads) || slices.Contains(got, absent) {
					t.Errorf("%s reading of %q = %q, want %q and not %q", mode.name, row.command, got, mode.reads, absent)
				}
			}
		})
	}
}

// rel-1-0-6:GAP-0880, GAP-0885 review 6: in the straight-line reading a read
// loop has the IFS that a top-level statement before the loop assigns; an IFS
// set in an uncalled function, a branch or after the loop is not followed. A
// top-level statement that does more than assign a value the reading knows
// leaves the full reading in place.
func TestSimpleCommandsStraightLineReadLoopIFSReachesOnlyFromTopLevel(t *testing.T) {
	const write = "sed -i x /r/$d/.defenseclaw/config.yaml"
	const stripped = "sed -i x \x27/r/home/.defenseclaw/config.yaml\x27"
	const kept = "sed -i x \x27/r/homex/.defenseclaw/config.yaml\x27"
	const read = "echo homex | while read -r d; do " + write + "; done"
	type reading struct{ stripped, kept bool }
	for _, row := range []struct {
		name, command  string
		straight, full reading
	}{
		{"default", read, reading{false, true}, reading{false, true}},
		{"assigned before", "IFS=x; " + read, reading{true, false}, reading{true, false}},
		{"exported before", "export IFS=x; " + read, reading{true, false}, reading{true, false}},
		{"assigned twice before", "IFS=y; IFS=x; " + read, reading{true, false}, reading{true, false}},
		{"known variable", "sep=x; IFS=$sep; " + read, reading{true, false}, reading{true, false}},
		{"unknown variable", "IFS=$(cat /x); " + read, reading{false, true}, reading{false, true}},
		{"set for the read", "echo homex | while IFS=x read -r d; do " + write + "; done", reading{true, false}, reading{true, false}},
		// Code that the shell may never run before the loop.
		{"assigned in a branch that does not run", "if false; then IFS=x; fi; " + read, reading{false, true}, reading{true, true}},
		{"assigned in a branch", "if test -f /x; then IFS=x; fi; " + read, reading{false, true}, reading{true, true}},
		{"assigned in a function never called", "f() { IFS=x; }; " + read, reading{false, true}, reading{false, true}},
		{"assigned in the loop after the read", "for i in 1 2; do " + read + "; if false; then IFS=x; fi; done", reading{false, true}, reading{true, true}},
		{"assigned in a function declared after the loop", "for i in 1 2; do " + read + "; f; done; f() { IFS=x; }", reading{false, true}, reading{true, true}},
		{"set by a function an uncalled function calls", "f() { IFS=x; }; for i in 1 2; do h() { f; }; " + read + "; done", reading{false, true}, reading{true, true}},
		{"set by a function the loop calls", "f() { IFS=x; }; for i in 1 2; do " + read + "; f; done", reading{false, true}, reading{true, true}},
		{"assigned after the loop", read + "; IFS=x", reading{false, true}, reading{false, true}},
		// The shell sets the IFS where the top-level statement stands, so a
		// function that reads with it runs with the IFS of its call.
		{"assigned at the top level before the call of the function that runs the loop", "f() { " + read + "; }; IFS=x; f", reading{true, false}, reading{true, false}},
		{"assigned before one call of the function and after another", "f() { " + read + "; }; f; IFS=x; f", reading{true, true}, reading{true, true}},
		{"assigned after the only call of the function", "f() { " + read + "; }; f; IFS=x", reading{false, true}, reading{false, true}},
		{"assigned before the call of a function that calls the one that runs the loop", "g() { f; }; f() { " + read + "; }; IFS=x; g", reading{true, false}, reading{true, false}},
		// A statement that spells the name without changing the IFS of the
		// shell: an argument that is printed, a prefix of one command.
		{"printed with echo", "echo IFS=x; " + read, reading{false, true}, reading{false, true}},
		{"set for one command only", "IFS=x env true; " + read, reading{false, true}, reading{false, true}},
		{"set for one function call only", "f() { :; }; IFS=x f; " + read, reading{false, true}, reading{false, true}},
		{"printed with printf", "printf \x27%s\\n\x27 IFS=x; " + read, reading{false, true}, reading{false, true}},
		{"printed with declare -p", "declare -p IFS; " + read, reading{false, true}, reading{false, true}},
		{"printed with echo before the function that runs the loop", "f() { " + read + "; }; echo IFS=x; f", reading{false, true}, reading{false, true}},
	} {
		t.Run(row.name, func(t *testing.T) {
			for _, mode := range []struct {
				name     string
				straight bool
				want     reading
			}{{"straight-line", true, row.straight}, {"full", false, row.full}} {
				got := simpleTextsOf(t, row.command, mode.straight)
				if has := slices.Contains(got, stripped); has != mode.want.stripped {
					t.Errorf("%s reading of %q: delimiter-stripped word = %v, want %v (%q)", mode.name, row.command, has, mode.want.stripped, got)
				}
				if has := slices.Contains(got, kept); has != mode.want.kept {
					t.Errorf("%s reading of %q: whole word = %v, want %v (%q)", mode.name, row.command, has, mode.want.kept, got)
				}
			}
		})
	}
}

// rel-1-0-6:GAP-0880, GAP-0885 review 8: in the straight-line reading a
// function that a loop runs is read with the state of every call the shell
// reaches, so a later call does not replace an earlier one; a call in code the
// shell never runs (a branch, a loop or the right side of && or || that the
// true and false builtins rule out) is no call.
func TestSimpleCommandsStraightLineFunctionRunsWithTheStateOfEachCallTheShellReaches(t *testing.T) {
	const write = "sed -i x /r/$d/.defenseclaw/config.yaml"
	const stripped = "sed -i x \x27/r/home/.defenseclaw/config.yaml\x27"
	const kept = "sed -i x \x27/r/homex/.defenseclaw/config.yaml\x27"
	const body = "f() { echo homex | while read -r d; do " + write + "; done; }; "
	for _, row := range []struct {
		name, command  string
		stripped, kept bool
	}{
		{"one call", body + "IFS=x; f", true, false},
		{"two calls with different IFS", body + "f; IFS=x; f", true, true},
		{"three calls", body + "f; IFS=x; f; unset IFS; f", true, true},
		{"later call in a branch that does not run", body + "f; IFS=x; if false; then f; fi", false, true},
		{"later call in the branch of an elif chain that does not run", body + "f; IFS=x; if true; then :; elif test -f /x; then f; fi", false, true},
		{"later call in an else that does not run", body + "f; IFS=x; if true; then :; else f; fi", false, true},
		{"later call after a failing command", body + "f; IFS=x; false && f", false, true},
		{"later call after a succeeding command", body + "f; IFS=x; true || f", false, true},
		{"later call after a negated command", body + "f; IFS=x; ! true && f", false, true},
		{"later call in a while that never runs", body + "f; IFS=x; while false; do f; done", false, true},
		{"later call in an until that never runs", body + "f; IFS=x; until true; do f; done", false, true},
		{"later call through a function in a branch that does not run", "g() { f; }; " + body + "f; IFS=x; if false; then g; fi", false, true},
		{"later call in a branch that may run", body + "f; IFS=x; if test -f /x; then f; fi", true, true},
		{"later call after a command that may fail", body + "f; IFS=x; test -f /x && f", true, true},
		{"later call in a branch of a false that a function replaces", "false() { :; }; " + body + "f; IFS=x; if false; then f; fi", true, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			got := simpleTextsOf(t, row.command, true)
			if has := slices.Contains(got, stripped); has != row.stripped {
				t.Errorf("reading of %q: delimiter-stripped word = %v, want %v (%q)", row.command, has, row.stripped, got)
			}
			if has := slices.Contains(got, kept); has != row.kept {
				t.Errorf("reading of %q: whole word = %v, want %v (%q)", row.command, has, row.kept, got)
			}
		})
	}
}
