// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"runtime"
	"strings"
	"testing"
)

// TestPipelineScopeNamesStayShort pins the linear split of a pipeline
// (GAP-0254): the stages of x | y | z are siblings, so the name of the
// scope of a stage does not grow with the stages before it. A scope per
// nesting level of the left-deep tree made the names of n stages n^2 bytes:
// a 67 KB pipeline held 6 GiB.
func TestPipelineScopeNamesStayShort(t *testing.T) {
	for _, stages := range []int{2, 3, 50, 500} {
		command := strings.Repeat("a | ", stages-1) + "a"
		statements, _, ok := sequenceStatementDetails(command, true, true, false, true)
		if !ok || len(statements) != stages {
			t.Fatalf("%d stages: ok=%t, %d statements", stages, ok, len(statements))
		}
		seen := map[string]bool{}
		for _, statement := range statements {
			if len(statement.scope) > 3+len("/s")+8 {
				t.Fatalf("%d stages: scope %q is %d bytes", stages, statement.scope, len(statement.scope))
			}
			if seen[statement.scope] {
				t.Fatalf("%d stages: two stages share the scope %q", stages, statement.scope)
			}
			seen[statement.scope] = true
		}
	}
}

// TestPipelineSplitGrowsLinearly doubles a pipeline and asserts the
// allocation of its split at most about triples.
func TestPipelineSplitGrowsLinearly(t *testing.T) {
	alloc := func(stages int) uint64 {
		command := strings.Repeat("a | ", stages-1) + "a"
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		sequenceStatementDetails(command, true, true, false, true)
		runtime.ReadMemStats(&after)
		return after.TotalAlloc - before.TotalAlloc
	}
	small, large := alloc(200), alloc(400)
	if large > 3*small+(1<<20) {
		t.Fatalf("200 stages allocate %d KiB, 400 stages %d KiB", small>>10, large>>10)
	}
}
