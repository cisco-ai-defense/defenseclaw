// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-0414 (review round 3, HLR3-SFX-*): sed -i with a backup suffix. The
// backup is a rename over a name the suffix builds, so a suffix that names
// the keys file replaces it. The rows are the reviewer's, built from the
// fixture paths: the control (a bare -i on an ordinary file) allows, and the
// three suffix spellings block in all four cells, in both startup
// environments, and each really replaces the keys file under real bash.
func TestGAP0414SedBackupSuffixRowsFourCellAndRealBash(t *testing.T) {
	for _, cell := range gap0293StartupCells {
		t.Run(cell.name, func(t *testing.T) {
			f := newB36ManagedHookFixture(t)
			gap0293SetStartup(t, cell.exported)
			base, dir := filepath.Base(f.keys), filepath.Dir(f.keys)
			operand := filepath.Join(f.project, base)
			writeOperand := func() {
				if err := os.WriteFile(operand, []byte("x\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			writeOperand()
			rows := []struct {
				id, command, want string
				changesKeys       bool
			}{
				{"HLR3-SFX-ctl", "sed -i s/x/y/ " + base, "allow", false},
				{"HLR3-SFX-a", "sed -i" + dir + "/* s/x/y/ " + base, "block", true},
				{"HLR3-SFX-b", "sed --in-place=" + dir + "/* s/x/y/ " + base, "block", true},
				{"HLR3-SFX-c", "sed -i../.ssh/* s/x/y/ " + base, "block", true},
				// the other spellings of the same suffix, by the option grammar
				{"HLR3-SFX-d-separate-cluster", "sed -ni" + dir + "/* s/x/y/ " + base, "block", true},
				// -in...: the suffix is "n/<dir>/*", a relative path that does not reach the
				// keys; real bash leaves them alone, so the reader must not block it
				{"HLR3-SFX-e-suffix-n", "sed -in" + dir + "/* s/x/y/ " + base, "allow", false},
			}
			var payloads [][]byte
			for _, r := range rows {
				payloads = append(payloads, f.payload(t, r.command))
			}
			headers := f.clientHeaders(t, payloads)
			var calls []*hookCall
			for i, r := range rows {
				calls = append(calls, everyMode(r.id, payloads[i], headers[i])...)
			}
			f.answerAll(t, calls)
			for i, call := range calls {
				if want := rows[i/4].want; call.verdict != want {
					t.Errorf("%s: got %s, want %s", call.name, call.verdict, want)
				}
			}
			// real bash and real sed: the rows that must block really replace the keys file
			if out, err := exec.Command("sed", "--version").Output(); err != nil || !strings.Contains(string(out), "GNU sed") {
				t.Skip("GNU sed not available for the real-bash check")
			}
			for _, r := range rows {
				if err := os.WriteFile(f.keys, []byte("# decoy\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				writeOperand()
				cmd := exec.Command("bash", "--norc", "--noprofile", "-c", r.command)
				cmd.Dir = f.project
				_ = cmd.Run()
				data, _ := os.ReadFile(f.keys)
				if changed := string(data) != "# decoy\n"; changed != r.changesKeys {
					t.Errorf("%s: real bash changed the keys file = %t, fixture says %t", r.id, changed, r.changesKeys)
				}
			}
		})
	}
}
