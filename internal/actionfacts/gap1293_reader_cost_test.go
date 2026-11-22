// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// gap1293MoverCalls is outer calls of f2, a definition and inner calls of f1,
// then a plain write. nested: f1 (the mover) is defined in the body of f2,
// so a call of f1 is defined only after a call of f2 that may have run
// (definedAt climbs to the calls of f2); otherwise both are defined at the
// top level and the text has the same statements.
func gap1293MoverCalls(calls int, nested bool) string {
	parts := make([]string, 0, 2*calls+2)
	for i := 0; i < calls; i++ {
		parts = append(parts, "f2")
	}
	if nested {
		parts = append(parts, "f2() { f1() { cd /tmp/w; }; }")
	} else {
		parts = append(parts, "f2() { :; }; f1() { cd /tmp/w; }")
	}
	for i := 0; i < calls; i++ {
		parts = append(parts, "f1")
	}
	parts = append(parts, "echo done > out.txt")
	return strings.Join(parts, "; ")
}

// rel-1-0-10:GAP-1293: the working-folder tracking of every parse of a text
// (posixWorkFolders, about 14 parses of the whole text per hook call) asked,
// for each call of a mover defined in another function's body, every call of
// that function before it again (definedAt): 400 calls of each took Analyze
// 6.7 ms against 1.1 ms, and nested mover definitions with 28 calls of each
// outer function made the Claude Code hook route about 10% slower than rel on
// a quiet box (1.4x under load). The earliest call of the outer function
// after which the definition may have run is now worked out once per scan,
// so a call of the inner function compares one offset, and a text with no
// function pays no tracking setup. The bound is relative, both texts timed
// in the same run (best of five, interleaved): the nested text may cost at
// most 3x the same calls with top-level definitions, plus 2 ms; the
// quadratic climb took over 6x at 500 calls of each.
func TestGAP1293NestedMoverCallsCostAsMuchAsTopLevelOnes(t *testing.T) {
	if raceDetector {
		t.Skip("timing bounds are for the plain build; -race runs this code many times slower")
	}
	const calls = 500
	nested := Input{Tool: "Bash", Command: gap1293MoverCalls(calls, true), CWD: "/home/alice/project", ActiveHome: "/home/alice"}
	flat := nested
	flat.Command = gap1293MoverCalls(calls, false)
	// The command facts stop at their own cap; the tracking reads the whole
	// parsed text, so only a node or depth bound would skip it.
	for _, input := range []Input{nested, flat} {
		if issues := Analyze(input).Parse.Issues; slices.Contains(issues, IssueNodeLimit) || slices.Contains(issues, IssueDepthLimit) {
			t.Fatalf("the text was not parsed in full: %v", issues)
		}
	}
	bestNested, bestFlat := time.Duration(1<<63-1), time.Duration(1<<63-1)
	for run := 0; run < 5; run++ {
		start := time.Now()
		Analyze(nested)
		bestNested = min(bestNested, time.Since(start))
		start = time.Now()
		Analyze(flat)
		bestFlat = min(bestFlat, time.Since(start))
	}
	bound := 3*bestFlat + 2*time.Millisecond
	t.Logf("calls=%d nested=%s top-level=%s bound=%s", calls, bestNested, bestFlat, bound)
	if bestNested > bound {
		t.Errorf("%d calls of a mover defined in the body of a function called %d times before: Analyze took %s, over %s (3x the same calls of top-level definitions, %s, plus 2 ms)",
			calls, calls, bestNested, bound, bestFlat)
	}
}
