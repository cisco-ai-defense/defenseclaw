// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"slices"
	"testing"
)

// A dd word that expands keeps "" in the argv, so the of= value is never
// read. It is still the output when its static text is of= or shows no key,
// and the model reads the call as a write (rel-1-0-10:GAP-1296): a reader
// of the model that skips programs with no write would otherwise skip dd
// of=$X. Another key (if=$X, bs=$N) is no output.
func TestDDExpandingOutputIsAWrite(t *testing.T) {
	for _, tc := range []struct {
		command string
		write   bool
	}{
		{"dd if=a.txt of=k", true},
		{"dd if=a.txt of=$(echo k)", true},
		{"dd if=a.txt of=${X:-k}", true},
		{"dd if=a.txt of=$UNSET", true},
		{"dd if=a.txt of=k[0-9]", true},
		{"dd if=a.txt of=k*", true},
		{`dd if=a.txt "$ARGS"`, true},
		{"dd if=$IN", false},
		{"dd if=a.txt bs=$N", false},
		{"dd if=a.txt", false},
	} {
		facts := Analyze(Input{Tool: "Bash", Command: tc.command, CWD: "/tmp", ActiveHome: "/home/u"})
		found := false
		for _, command := range facts.Commands {
			if command.Program == "dd" {
				found = true
				if got := slices.Contains(command.Operations, OperationWrite); got != tc.write {
					t.Errorf("%q: write=%v (ops %v), want %v", tc.command, got, command.Operations, tc.write)
				}
			}
		}
		if !found {
			t.Errorf("%q: no dd command fact", tc.command)
		}
	}
}
