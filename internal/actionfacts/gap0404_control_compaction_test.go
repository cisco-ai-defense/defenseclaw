// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

// A later shell word can use HOME or PWD without spelling the variable name:
// ~ expands HOME and ~+ expands PWD. Dead ordinary values may be discarded.
func TestGAP0404CompactionKeepsImplicitHomeAndPWD(t *testing.T) {
	states := []simpleShellState{
		{cwd: "/work", vars: map[string]string{"HOME": "/home/alice", "PWD": "/work", "dead": "a"}},
		{cwd: "/work", vars: map[string]string{"HOME": "/home/alice", "PWD": "/work", "dead": "b"}},
	}
	remaining := []sequenceStatement{{text: `echo m > ~/note; echo m > ~+/note`}}
	got := compactSimpleStatesForFuture(states, remaining, true)
	if len(got) != 1 || got[0].vars["HOME"] != "/home/alice" || got[0].vars["PWD"] != "/work" {
		t.Fatalf("compaction discarded an implicit shell directory value: %+v", got)
	}
	if _, ok := got[0].vars["dead"]; ok {
		t.Fatalf("compaction retained a dead ordinary value: %+v", got)
	}
}
