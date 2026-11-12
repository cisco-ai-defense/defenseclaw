// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"
	"testing"
)

// rel-1-0-6:GAP-0630 integration: USER and LOGNAME hold the login the home
// spells only as a guess. The per-command readings keep an unassigned name as
// the word the shell expands at run time, and add the guess reading, marked
// LoginGuess, for the proof of a write to protected state. A name the action
// assigns is read as assigned, and a command that names neither has no second
// reading.
func TestSimpleCommandsReadsAnUnassignedLoginAsRuntimeAndAddsTheGuessReading(t *testing.T) {
	for _, row := range []struct {
		name, command string
		runtime       []string // texts of the readings without the guess
		guess         []string // texts of the LoginGuess readings
	}{
		// A lone command has no second reading to make; the readers of the action itself
		// read the names.
		{"user alone", "echo marker $USER", nil, nil},
		{"logname alone", "echo marker ${LOGNAME}", nil, nil},
		{"user after an unrelated export", "export PATH=$DIR; echo marker $USER",
			[]string{"export PATH=$DIR", "echo marker $USER"}, []string{"echo marker 'alice'"}},
		{"user in an && list", "echo marker $USER && echo done",
			[]string{"echo marker $USER", "echo done"}, []string{"echo marker 'alice'"}},
		{"user in a target", "echo marker > /var/tmp/dc-$USER.txt; echo done",
			[]string{"echo marker > /var/tmp/dc-$USER.txt", "echo done"}, []string{"echo marker > '/var/tmp/dc-alice.txt'"}},
		// Assigned in the action: the value is the shell's, not a guess.
		{"user assigned", "USER=bob; echo marker $USER", []string{"echo marker 'bob'"}, nil},
		{"user assigned to the home name", "USER=alice; echo marker $USER", []string{"echo marker 'alice'"}, nil},
		// Benign twins: no login name, no second reading.
		{"home", "echo marker $HOME; echo done", []string{"echo marker '/home/alice'", "echo done"}, nil},
		{"plain list", "echo marker && echo done", []string{"echo marker", "echo done"}, nil},
	} {
		t.Run(row.name, func(t *testing.T) {
			input := Input{Tool: "Bash", Command: row.command, CWD: "/home/alice/project",
				ActiveHome: "/home/alice", DialectHint: DialectPOSIX}
			var runtime, guess []string
			for _, simple := range SimpleCommands(input, Analyze(input)) {
				if simple.EvaluationFailure != "" {
					t.Fatalf("%q: evaluation failure %q", row.command, simple.EvaluationFailure)
				}
				if simple.LoginGuess {
					guess = append(guess, simple.Text)
				} else {
					runtime = append(runtime, simple.Text)
				}
			}
			if strings.Join(runtime, "|") != strings.Join(row.runtime, "|") {
				t.Errorf("%q: readings without the guess = %q, want %q", row.command, runtime, row.runtime)
			}
			if strings.Join(guess, "|") != strings.Join(row.guess, "|") {
				t.Errorf("%q: guess readings = %q, want %q", row.command, guess, row.guess)
			}
		})
	}
}
