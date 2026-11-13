// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
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
// known: with no startup it gives each row's answer, and with an inherited
// exported function in the environment (the host's own, which RHEL and the
// shared dev host export) it is declined for every row. Both cells set the
// environment in the test; the host's is cleared first.
func TestActionClientDeadValueProofDeclinesChangedShellExpansion(t *testing.T) {
	// The proof needs an absolute working directory, as every hook reports;
	// /tmp/project is not one on Windows.
	root := t.TempDir()
	cwd, home := filepath.Join(root, "project"), filepath.Join(root, "home")
	for _, cell := range []struct {
		id       string
		exported bool
	}{{"no-startup", false}, {"exported-function", true}} {
		t.Run(cell.id, func(t *testing.T) {
			clearShellStartupEnv(t)
			if cell.exported {
				t.Setenv("BASH_FUNC_s7probe%%", "() {  :\n}")
			}
			for _, row := range hlinkmatrix.DeadValueRows() {
				t.Run(row.ID, func(t *testing.T) {
					want := row.ProvedSafe && !cell.exported
					if got := actionClientProvedSafeVariableTargets(row.Command, cwd, home); got != want {
						t.Errorf("proof %v, want %v for %q", got, want, row.Command)
					}
				})
			}
		})
	}
}
