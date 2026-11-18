// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv/hlinkmatrix"
)

// GAP-0415 (review round 3): managed is never weaker than per-user. The rows
// are the reviewer's, generated from the corpus: HLR3-W-<writer>-<row> swaps
// the verb of every protected chmod row for the other metadata and content
// writers; the class rows respell the unmatched hard-link name under the
// glob options of the reviewer's variants (shopt, set -f, GLOBIGNORE); and
// every variable row runs inside a nested bash -c and sh -c. Each row runs in
// all four cells and both startup environments, and answerAll holds every
// managed answer to at least its per-user twin (managedAtLeastPerUser).
func TestGAP0415ManagedNeverWeakerThanPerUser(t *testing.T) {
	for _, cell := range gap0293StartupCells {
		t.Run(cell.name, func(t *testing.T) {
			f := newB36ManagedHookFixture(t)
			gap0293SetStartup(t, cell.exported)
			names := hlinkmatrix.DefaultNames()
			hlinkmatrix.Setup(t, f.project, f.keys, names)
			type row struct{ id, command string }
			var rows []row
			pinned := map[string]bool{}
			for _, r := range hlinkmatrix.Rows(names) {
				if strings.HasSuffix(r.ID, "-chmod") && r.Protected() {
					for _, w := range hlinkmatrix.Writers() {
						id := "HLR3-W-" + w.ID + "-" + strings.TrimPrefix(r.ID, "HL-")
						rows = append(rows, row{id, strings.Replace(r.Command, "chmod 600 ", w.Prefix, 1)})
						switch w.ID {
						case "chattr", "setfacl", "setfattr", "shred", "sort-o":
							if r.ID == "HL-var-hard-chmod" || r.ID == "HL-var-sym-chmod" {
								pinned[id] = true
							}
						}
					}
				}
				if strings.HasPrefix(r.ID, "HL-var-") && r.Protected() {
					for _, shell := range []string{"bash", "sh"} {
						rows = append(rows, row{"HL3-wrap-" + shell + "-" + strings.TrimPrefix(r.ID, "HL-"), shell + " -c " + shellSingleQuote(r.Command)})
					}
				}
			}
			for _, v := range hlinkmatrix.Rev2ClassVariants(names) {
				if v.Env == nil && strings.Contains(v.Transform, "+") && !strings.HasSuffix(v.Transform, "+none") {
					rows = append(rows, row{"HL3-class-" + v.ID, v.Command})
				}
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
			if len(pinned) != 10 {
				t.Errorf("the reviewer's ten pinned rows: %d", len(pinned))
			}
			for i, call := range calls {
				id := rows[i/4].id
				if pinned[id] && call.verdict != "block" {
					t.Errorf("%s: got %s, want block", call.name, call.verdict)
				}
			}
			if len(rows) < 150 {
				t.Errorf("only %d rows generated", len(rows))
			}
		})
	}
}

// shellSingleQuote is the word text of s as one single-quoted shell word.
func shellSingleQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
