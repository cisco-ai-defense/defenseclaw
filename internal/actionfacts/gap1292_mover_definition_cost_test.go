// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// gap1292NestedMovers is a benign text with levels nested function
// definitions around a cd (f<levels>() { ... f1() { cd /tmp/w; }; ... }),
// outerCalls calls of each enclosing function before the definition and
// innerCalls calls of the innermost one after it, then a plain write.
func gap1292NestedMovers(levels, outerCalls, innerCalls int) string {
	var parts []string
	for level := levels; level >= 2; level-- {
		for i := 0; i < outerCalls; i++ {
			parts = append(parts, fmt.Sprintf("f%d", level))
		}
	}
	definition := "f1() { cd /tmp/w; }"
	for level := 2; level <= levels; level++ {
		definition = fmt.Sprintf("f%d() { %s; }", level, definition)
	}
	parts = append(parts, definition)
	for i := 0; i < innerCalls; i++ {
		parts = append(parts, "f1")
	}
	parts = append(parts, "echo done > out.txt")
	return strings.Join(parts, "; ")
}

// rel-1-0-10:GAP-1292: workFolderTracker.definedAt (rel-1-0-10:GAP-1229)
// climbed every call of each enclosing function again for every call of the
// inner one, with no memo, so nested mover definitions with many calls of
// each outer function cost the product of those counts: five levels, 24
// calls of each outer function and 20 of the inner one took Analyze 120 ms
// and the Claude Code hook route 2369 ms (rel 92 ms). Each answer is now
// worked out once per scan, so the cost grows with the number of levels,
// not as a power of the call counts. The bound (8 ms per level for Analyze
// plus SimpleCommands, the best of three runs) is over 10x what the fixed
// code takes at every level on a loaded box (about 2 ms), and the
// unmemoized climb took about 240 ms at five levels.
func TestGAP1292NestedMoverDefinitionsCostLinearInDepth(t *testing.T) {
	if raceDetector {
		t.Skip("timing bounds are for the plain build; -race runs this code many times slower")
	}
	// Five levels, 24 and 20 calls: 118 statements, inside the statement
	// budget, so every level is read and not cut to one capped statement.
	const outerCalls, innerCalls = 24, 20
	const perLevel = 8 * time.Millisecond
	for levels := 1; levels <= maxWorkFolderCallDepth+1; levels++ {
		input := Input{Tool: "Bash", Command: gap1292NestedMovers(levels, outerCalls, innerCalls),
			CWD: "/home/alice/project", ActiveHome: "/home/alice"}
		best := time.Duration(1<<63 - 1)
		var simples []SimpleCommand
		for run := 0; run < 3; run++ {
			start := time.Now()
			simples = SimpleCommands(input, Analyze(input))
			if took := time.Since(start); took < best {
				best = took
			}
		}
		bound := time.Duration(levels) * perLevel
		t.Logf("levels=%d statements=%d took=%s bound=%s", levels, len(simples), best, bound)
		if len(simples) <= innerCalls {
			t.Fatalf("%d levels: %d simple commands, the text was not read in full (over a budget?)", levels, len(simples))
		}
		if best > bound {
			t.Errorf("%d nested mover definitions (%d calls of each outer one, %d of the inner one): Analyze + SimpleCommands took %s, over %s (linear in the levels)",
				levels, outerCalls, innerCalls, best, bound)
		}
	}
}
