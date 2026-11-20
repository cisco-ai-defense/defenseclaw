// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv/hlinkmatrix"
)

func TestActionClientWriteCandidate(t *testing.T) {
	for _, row := range []struct {
		command string
		want    bool
	}{
		{"format source.go", false},
		{"terraform plan", false},
		{"npm run build 2>&1", false},
		{"go test ./... > build/test.log 2>&1", true},
		{"echo x >& build/out.log", true},
		{"rm -f sshlink/authorized_keys", true},
		{"pwsh -c \"Set-Content -Path keylink -Value k\"", true},
	} {
		if got := actionClientWriteCandidate(row.command); got != row.want {
			t.Errorf("%q: candidate %v, want %v", row.command, got, row.want)
		}
	}
}

// The dead-value proof removes a block, so it holds only when the shell is
// known. With no startup it gives each row's answer. With an exported
// function that a call of the row runs (the row's echo, install or rsync),
// it is declined for every row. With an exported function no call of the
// row runs (the host's own, like the module function that RHEL and the
// shared dev host export), each row keeps its answer: a function no
// statement calls changes nothing (rel-1-0-10:GAP-0276). Every cell sets the
// environment in the test after it clears the host's.
func TestActionClientDeadValueProofDeclinesChangedShellExpansion(t *testing.T) {
	// The proof needs an absolute working directory, as every hook reports;
	// /tmp/project is not one on Windows.
	root := t.TempDir()
	cwd, home := filepath.Join(root, "project"), filepath.Join(root, "home")
	for _, cell := range []struct {
		id string
		// function names the function exported for a row (nil: none).
		function func(t *testing.T, row hlinkmatrix.DeadValueRow) string
		called   bool
	}{
		{"no-startup", nil, false},
		{"unrelated-exported-function", func(*testing.T, hlinkmatrix.DeadValueRow) string { return "s7probe" }, false},
		{"called-exported-function", func(t *testing.T, row hlinkmatrix.DeadValueRow) string {
			return deadValueRowProgram(t, row.Command)
		}, true},
	} {
		t.Run(cell.id, func(t *testing.T) {
			clearShellStartupEnv(t)
			for _, row := range hlinkmatrix.DeadValueRows() {
				t.Run(row.ID, func(t *testing.T) {
					function := ""
					if cell.function != nil {
						function = cell.function(t, row)
						t.Setenv("BASH_FUNC_"+function+"%%", "() {  :\n}")
					}
					want := row.ProvedSafe && !cell.called
					if got := actionClientProvedSafeVariableTargets(row.Command, cwd, home); got != want {
						t.Errorf("proof %v, want %v for %q with exported function %q", got, want, row.Command, function)
					}
				})
			}
		})
	}
}

// deadValueRowProgram is the program of a dead-value row's write: the first
// word of its last statement (echo, install, rsync).
func deadValueRowProgram(t *testing.T, command string) string {
	t.Helper()
	fields := strings.Fields(command[strings.LastIndexByte(command, ';')+1:])
	if len(fields) == 0 || strings.Contains(fields[0], "=") {
		t.Fatalf("no program word in the last statement of %q", command)
	}
	return fields[0]
}
