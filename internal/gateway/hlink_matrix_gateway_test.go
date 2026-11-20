// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv/hlinkmatrix"
)

// GAP-0293 regression corpus through the four hook cells. Every row of the
// shared matrix (hlinkmatrix: each verb on each link name in each quoting
// form and layout) is held to its effect in all four cells, in both
// startup environments: a row that reaches the protected inode blocks, a
// row that does not allows. answerAll also holds every managed answer to be
// at least its per-user twin (managedAtLeastPerUser).
func TestHLinkMatrixFourCell(t *testing.T) {
	for _, cell := range gap0293StartupCells {
		t.Run(cell.name, func(t *testing.T) {
			f := newB36ManagedHookFixture(t)
			gap0293SetStartup(t, cell.exported)
			names := hlinkmatrix.DefaultNames()
			hlinkmatrix.Setup(t, f.project, f.keys, names)
			rows := hlinkmatrix.Rows(names)
			var payloads [][]byte
			for _, row := range rows {
				payloads = append(payloads, f.payload(t, row.Command))
			}
			headers := f.clientHeaders(t, payloads)
			var calls []*hookCall
			for i, row := range rows {
				calls = append(calls, everyMode(row.ID, payloads[i], headers[i])...)
			}
			f.answerAll(t, calls)
			missed := map[string][]string{}
			falseBlock := map[string][]string{}
			for i, call := range calls {
				row := rows[i/4]
				cellName := call.connector + "/managed=" + map[bool]string{true: "true", false: "false"}[call.managed]
				switch {
				case row.Protected() && call.verdict != "block":
					missed[cellName] = append(missed[cellName], row.ID)
				case !row.Protected() && call.verdict == "block":
					falseBlock[cellName] = append(falseBlock[cellName], row.ID)
				}
			}
			report := func(kind string, byCell map[string][]string) {
				var cells []string
				for name := range byCell {
					cells = append(cells, name)
				}
				sort.Strings(cells)
				for _, name := range cells {
					ids := byCell[name]
					sort.Strings(ids)
					t.Errorf("%s %s: %d rows: %s", kind, name, len(ids), strings.Join(ids, ", "))
				}
			}
			report("protected row allowed", missed)
			report("benign row blocked", falseBlock)
			if data, err := os.ReadFile(f.keys); err != nil || string(data) != "# decoy\n" {
				t.Fatalf("decoy keys file changed: %q %v", data, err)
			}
		})
	}
}
