// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"testing"
)

// W24 loop round 4: a program word bound by the assignment just before it
// is also known when the call heads a list (x=ls; "$x" && echo done). A
// value the action computes at run time, and a protected write through the
// bound program, still get a decision.
func TestActionDecisionBoundProgramHeadsList(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cwd := filepath.Join(home, "project")
	for _, tc := range []struct {
		command string
		decided bool
	}{
		{`x=ls; "$x" && echo done`, false},
		{`x=ls; $x -la || echo failed`, false},
		{`x=ls; ${x} && echo a && echo b`, false},
		{`x=$(cat name); "$x" && echo done`, true},
		{`x=tee; "$x" -a ~/.ssh/authorized_keys && echo done`, true},
		{`x=ls; ! "$x" && echo done`, true},
	} {
		if got := ActionCommandDecision(tc.command, cwd, home); (got != "") != tc.decided {
			t.Errorf("%q decision = %q, want decided=%v", tc.command, got, tc.decided)
		}
	}
}
