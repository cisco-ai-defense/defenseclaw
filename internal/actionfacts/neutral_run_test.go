// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"
	"testing"
)

// A run of context-neutral wrappers is read in one walk: the command at its
// end carries every wrapper of the run, outermost first, and the cost of the
// reading grows linearly with the run, not with its cube (rel-1-0-10:GAP-0977;
// the run spends no wrapper depth, substrate-1:GAP-0334).
func TestNeutralWrapperRunIsReadInOneWalk(t *testing.T) {
	chain := func(n int) []string {
		argv := strings.Fields(strings.Repeat("nohup nice -n 5 timeout 5 time ", n/4))
		return append(argv, "cat", "notes.txt")
	}
	out := analyzeStructuredArgv(chain(64), 1, 0, DialectArgv)
	if out.status == StatusLimitExceeded {
		t.Fatalf("a 64-deep neutral run is within InlineChainWrappers: status %s", out.status)
	}
	var cat *CommandFact
	for i := range out.commands {
		if out.commands[i].Program == "cat" {
			cat = &out.commands[i]
		}
	}
	if cat == nil || len(cat.Wrappers) != 64 {
		t.Fatalf("cat behind 64 neutral wrappers: got %+v", cat)
	}
	for i, want := range []string{"nohup", "nice", "timeout", "time"} {
		if cat.Wrappers[i].Executable != want {
			t.Errorf("wrapper %d is %q, want %q (outermost first)", i, cat.Wrappers[i].Executable, want)
		}
	}
	// The innermost wrapper runs `time cat notes.txt`.
	if got := len(cat.Wrappers[63].Argv); got != 3 {
		t.Errorf("innermost wrapper argv has %d words, want 3", got)
	}
	small := testing.AllocsPerRun(5, func() { analyzeStructuredArgv(chain(8), 1, 0, DialectArgv) })
	large := testing.AllocsPerRun(5, func() { analyzeStructuredArgv(chain(64), 1, 0, DialectArgv) })
	if large > 12*small {
		t.Errorf("allocations: 8-deep run %.0f, 64-deep run %.0f: more than linear in the run", small, large)
	}
}
