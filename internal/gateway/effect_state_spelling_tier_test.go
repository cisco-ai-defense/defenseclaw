// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"testing"
)

// TestProvenStateWriteSpellingsShareTheOwnerTier: every proven spelling of a
// write to a DefenseClaw state member gets the owner tier of
// tamper.detector_state_write (GAP-0747, owner 2026-11-14; owner tiering
// 2026-11-19T20:58Z): an alert in the default, permissive and managed
// default tiers, a block in strict and managed strict, with the effects
// lane as shipped. The a64bfdb931 lane-on block in every tier (GAP-1239,
// GAP-1274 lane-on rows) predates those rulings (DET111 ruling
// 2026-11-24T21:57Z). The benign twins, the same call with its folder in
// /tmp, keep that cell too.
func TestProvenStateWriteSpellingsShareTheOwnerTier(t *testing.T) {
	home := r2Home(t)
	rows := det111R2Rows(t, home,
		"det111/GAP-1239/seed-shell-redirect/seed",
		"det111/GAP-1274/seed-abs-state/seed",
		"det111/GAP-1274/sudo-D-state/var",
		"det111/GAP-1274/sudo-chdir-state/var",
		"det111/GAP-1239/awk-plain/var",
		"det111/GAP-1239/sudo-awk/var",
		"det111/GAP-1274/sudo-D-tmp-benign/twin",
		"det111/GAP-1274/sudo-chdir-tmp-benign/twin",
	)
	state := home + "/.defenseclaw/config.yaml"
	for id, cmd := range map[string]string{
		"spelling/append":   "echo x >> " + state,
		"spelling/cd-first": "cd ~/.defenseclaw && echo x >> config.yaml",
		"spelling/python":   `python3 -c 'import os;os.remove("` + state + `")'`,
		"spelling/cp":       "cp /tmp/x " + state,
		"spelling/sed-i":    "sed -i s/a/b/ " + state,
		"spelling/tee":      "echo x | tee " + state,
		"spelling/rm":       "rm -f " + state,
	} {
		rows = append(rows, r2Row{id: id, cmd: cmd, cwd: home})
	}
	r2Cells(t, rows, func(_, tier string) string {
		if r2Strict(tier) {
			return "block"
		}
		return "alert"
	})
}
