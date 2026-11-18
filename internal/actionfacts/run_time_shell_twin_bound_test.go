// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"
	"testing"
	"time"

	"mvdan.cc/sh/v3/syntax"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

// gap1041Word is a program word that nests levels command substitutions
// around seed: "$(which $(which ... seed))".
func gap1041Word(seed string, levels int) string {
	inner := seed
	for i := 0; i < levels; i++ {
		inner = "$(which " + inner + ")"
	}
	return `"` + inner + `"`
}

// gap1041Budget is the time one reading of a nested word may take. The
// reading is linear in the word (a few milliseconds at the bound); before
// rel-1-0-10:GAP-1041 it doubled per level and took 46 s at 22 levels.
const gap1041Budget = 500 * time.Millisecond

// TestRunTimeShellTwinNestedSubstitutionsBounded: each program word is
// expanded once, so nested substitutions cost one reading per level, and a
// word nested past the depth bound is TRUNCATED (rel-1-0-10:GAP-1041).
func TestRunTimeShellTwinNestedSubstitutionsBounded(t *testing.T) {
	const body = ` -c 'echo hi'`
	read := func(t *testing.T, command string) (string, bool, bounded.CapSet) {
		t.Helper()
		start := time.Now()
		twin, ok, caps := RunTimeShellTwin(command)
		if elapsed := time.Since(start); elapsed > gap1041Budget {
			t.Errorf("reading took %v, budget %v", elapsed, gap1041Budget)
		}
		return twin, ok, caps
	}
	for _, levels := range []int{1, 15, 20, 22, 30, maxRunTimeShellWordDepth} {
		// A shell named at the innermost level is named through every level.
		twin, ok, caps := read(t, gap1041Word("bash", levels)+body)
		if !ok || twin != "bash"+body || caps.Any() {
			t.Errorf("%d levels, shell seed: RunTimeShellTwin = %q, %v, %v; want %q and no cap", levels, twin, ok, caps, "bash"+body)
		}
		// An unknown innermost word stays unknown, with no cap.
		if twin, ok, caps := read(t, gap1041Word("$T", levels)+body); ok || caps.Any() {
			t.Errorf("%d levels, unknown seed: RunTimeShellTwin = %q, %v, %v; want no reading and no cap", levels, twin, ok, caps)
		}
	}
	for _, levels := range []int{maxRunTimeShellWordDepth + 1, 2 * maxRunTimeShellWordDepth} {
		for _, seed := range []string{"bash", "$T"} {
			twin, ok, caps := read(t, gap1041Word(seed, levels)+body)
			if ok || !caps.Has(bounded.Depth) {
				t.Errorf("%d levels, seed %s: RunTimeShellTwin = %q, %v, %v; want no reading, TRUNCATED cap=depth", levels, seed, twin, ok, caps)
			}
		}
	}
}

// TestRunTimeShellWordReadsEachWordOnce: the two expansions of a word share
// the reading of the words nested in it, so a nested word is read once.
func TestRunTimeShellWordReadsEachWordOnce(t *testing.T) {
	for _, levels := range []int{4, 20, maxRunTimeShellWordDepth} {
		file, ok := shellparse.Parse(gap1041Word("$T", levels) + " -c true")
		if !ok {
			t.Fatalf("%d levels: parse failed", levels)
		}
		call, isCall := file.Stmts[0].Cmd.(*syntax.CallExpr)
		if !isCall {
			t.Fatalf("%d levels: not a call", levels)
		}
		var trunc bounded.Truncated
		reader := newShellWordReader(&trunc)
		if _, known := reader.read(call.Args[0], true, "", 0); known {
			t.Fatalf("%d levels: unknown seed read as a shell", levels)
		}
		// One reading per level: the program word and the word of each
		// which operand down to the seed.
		if got := len(reader.memo); got != levels+1 {
			t.Errorf("%d levels: %d words read, want %d", levels, got, levels+1)
		}
		if trunc.Set(&reader.words).Any() {
			t.Errorf("%d levels: cap hit under the bound", levels)
		}
	}
}

// TestRunTimeShellTwinWordBudget: a reading expands at most
// maxRunTimeShellWords program words; one more is TRUNCATED cap=nodes.
func TestRunTimeShellTwinWordBudget(t *testing.T) {
	statements := func(n int) string { return strings.Repeat("$a; ", n-1) + "\"$SHELL\" -c true" }
	if _, ok, caps := RunTimeShellTwin(statements(maxRunTimeShellWords)); !ok || caps.Any() {
		t.Errorf("at the budget: ok=%v caps=%v; want a reading and no cap", ok, caps)
	}
	if _, _, caps := RunTimeShellTwin(statements(maxRunTimeShellWords + 1)); !caps.Has(bounded.Nodes) {
		t.Errorf("past the budget: caps=%v; want TRUNCATED cap=nodes", caps)
	}
}
