// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// rel-1-0-6:GAP-0880, GAP-0885 round 11: the client lists the straight-line
// readings of a command that declares a function or spells IFS, whichever way
// the parser accepts the declaration; a plain command pays nothing for them.
func TestStraightLineReadingsAreChosenFromTheSyntaxTree(t *testing.T) {
	for _, row := range []struct {
		name, command string
		listed        bool
	}{
		{"parentheses", "f() { " + "read d <<< alice; sed -i s/a/b/ /home/$d/config.yaml; }; f; read() { :; }; f", true},
		{"spaced parentheses", "f ( ) { " + "read d <<< alice; sed -i s/a/b/ /home/$d/config.yaml; }; f; read ( ) { :; }; f", true},
		{"keyword and tab", "function\tf { read d <<< alice; sed -i s/a/b/ /home/$d/config.yaml; }; f; function\tread { :; }; f", true},
		{"IFS in quotes", "declare I\"F\"S=x; sed -i s/a/b/ /home/x/config.yaml", true},
		{"plain command", "sed -i s/a/b/ /home/alice/config.yaml", false},
		{"plain loop", "for d in alice bob; do sed -i s/a/b/ /home/$d/config.yaml; done", false},
	} {
		input := actionfacts.Input{Tool: "Bash", Command: row.command, CWD: "/home/alice", ActiveHome: "/home/alice"}
		if got := len(straightLineReadings(input, row.command)) > 0; got != row.listed {
			t.Errorf("%s: readings listed = %v, want %v", row.name, got, row.listed)
		}
	}
}
