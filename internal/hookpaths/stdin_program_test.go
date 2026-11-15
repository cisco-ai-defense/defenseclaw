// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"slices"
	"testing"
)

// StatementProgram: the command word of a statement prefix, behind the
// wrappers that pass argv on, never a word of its operands.
func TestStatementProgram(t *testing.T) {
	for _, tc := range []struct {
		statement string
		program   string
		args      []string
		known     bool
	}{
		{"bash", "bash", []string{}, true},
		{"sudo -n bash -s", "bash", []string{"-s"}, true},
		{"sudo bash -c", "bash", []string{"-c"}, true},
		{"env a=1 /bin/sh -e", "sh", []string{"-e"}, true},
		{"nohup nice bash", "bash", []string{}, true},
		{"FOO=1 bash -eu", "bash", []string{"-eu"}, true},
		{"grep bash", "grep", []string{"bash"}, true},
		{"which bash", "which", []string{"bash"}, true},
		{"echo run sh", "echo", []string{"run", "sh"}, true},
		{"ssh host bash", "ssh", []string{"host", "bash"}, true},
		{"bash run.sh", "bash", []string{"run.sh"}, true},
		{"$SHELL -s", "", nil, false},
		{"", "", nil, false},
	} {
		program, args, known := StatementProgram(tc.statement, "/home/u")
		if program != tc.program || known != tc.known || known && !slices.Equal(args, tc.args) {
			t.Errorf("StatementProgram(%q) = %q %q %v, want %q %q %v", tc.statement, program, args, known, tc.program, tc.args, tc.known)
		}
	}
}
