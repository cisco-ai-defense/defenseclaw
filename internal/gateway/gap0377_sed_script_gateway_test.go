// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv/hlinkmatrix"
)

// GAP-0377: the replace-verb proof reads the sed script. A sed -i whose
// script writes or runs something that reaches the keys file blocks in all
// four cells, in both startup environments, with the proof held or refused
// by the script alone. The rows are the corpus' sed -i rows (every quoting
// of every protected name) with the script swapped in code; the ordinary
// control keeps its replace-only script and allows.
func TestGAP0377SedScriptThatReachesTheKeysBlocksFourCell(t *testing.T) {
	for _, cell := range gap0293StartupCells {
		t.Run(cell.name, func(t *testing.T) {
			f := newB36ManagedHookFixture(t)
			gap0293SetStartup(t, cell.exported)
			names := hlinkmatrix.DefaultNames()
			hlinkmatrix.Setup(t, f.project, f.keys, names)
			type sedRow struct {
				id, command, want string
			}
			var rows []sedRow
			for _, row := range hlinkmatrix.Rows(names) {
				if !strings.HasSuffix(row.ID, "-sed-i") || !strings.HasPrefix(row.Command, "sed -i s/x/y/ ") {
					continue
				}
				operand := strings.TrimPrefix(row.Command, "sed -i s/x/y/ ")
				if row.Target == hlinkmatrix.Ordinary {
					rows = append(rows, sedRow{row.ID + "/replace-only", row.Command, "allow"})
					continue
				}
				if row.Target != hlinkmatrix.Alias {
					continue
				}
				for _, script := range []struct{ id, text string }{
					{"w", "w " + f.keys}, {"W", "W " + f.keys}, {"s-w", "s/x/y/w " + f.keys},
					{"w-link", "w " + names.KeyHard}, {"e", "e touch " + f.keys},
				} {
					rows = append(rows, sedRow{row.ID + "/" + script.id, "sed -i '" + script.text + "' " + operand, "block"})
				}
			}
			var payloads [][]byte
			for _, row := range rows {
				payloads = append(payloads, f.payload(t, row.command))
			}
			headers := f.clientHeaders(t, payloads)
			var calls []*hookCall
			for i, row := range rows {
				calls = append(calls, everyMode(row.id, payloads[i], headers[i])...)
			}
			f.answerAll(t, calls)
			bad := 0
			for i, call := range calls {
				if want := rows[i/4].want; call.verdict != want {
					if bad++; bad <= 20 {
						t.Errorf("%s: got %s, want %s", call.name, call.verdict, want)
					}
				}
			}
			if bad > 20 {
				t.Errorf("... %d wrong cells in all", bad)
			}
			if len(rows) < 100 {
				t.Errorf("only %d rows generated", len(rows))
			}
		})
	}
}
