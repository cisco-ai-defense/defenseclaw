// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/toolshape"
)

// The page-script reader spends one work budget (bounded.Time) on every scan
// that can cross many tokens, so a script built to make each of them cross the
// rest of the script is TRUNCATED, never read in part and called clean. The
// lane counts in work units of its own family: a script of size nested calls
// still open at its end, each of whose argument scans crosses the rest of the
// script, so the work is quadratic in size and the budget (1<<22 steps) is
// spent at pageScriptWorkLimit nesting levels (TestPageScriptWorkLaneLimit
// pins that number; when the reader's cost changes, it says so).
const pageScriptWorkLimit = 1448

func init() {
	registerBoundedLane(
		boundedLaneCap{lane: "s7/browserjs page-script-work", cap: bounded.Time, limit: pageScriptWorkLimit,
			gen: pageScriptWorkCall, seen: pageScriptSeenCall, work: true},
	)
}

// pageScriptWorkScript is a state read and size calls left open.
func pageScriptWorkScript(size int) string {
	return "const s = document.cookie;\n" + strings.Repeat("fetch(", size)
}

// pageScriptWorkCall is a page script of size nested calls.
func pageScriptWorkCall(size int, shape boundedShape) (boundedLaneCall, bool) {
	if shape.nested || shape.multi || shape.seenAfter {
		return boundedLaneCall{}, false
	}
	input := map[string]any{"function": pageScriptWorkScript(size)}
	if shape.seen {
		input["path"] = nonShellSeenPath
	}
	return boundedLaneCall{tool: pgPlaywright + "browser_evaluate", input: input}, true
}

// The lane's limit is the last size the budget reads whole: the next level is
// truncated, and truncated for the time cap alone (no byte or token bound is
// near).
func TestPageScriptWorkLaneLimit(t *testing.T) {
	at := toolshape.AnalyzePageScript(pageScriptWorkScript(pageScriptWorkLimit))
	if at.Truncated.Any() {
		t.Fatalf("%d nested calls are truncated (%v): lower pageScriptWorkLimit to the last size read whole", pageScriptWorkLimit, at.Truncated)
	}
	past := toolshape.AnalyzePageScript(pageScriptWorkScript(pageScriptWorkLimit + 1))
	if !past.Truncated.Has(bounded.Time) {
		t.Fatalf("%d nested calls are not truncated (%v): raise pageScriptWorkLimit to the last size read whole", pageScriptWorkLimit+1, past.Truncated)
	}
	if past.Truncated.Has(bounded.Bytes) || past.Truncated.Has(bounded.Nodes) {
		t.Fatalf("the work lane hit a byte or token bound: %v", past.Truncated)
	}
}
