// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// gap1281PaddedCall is a Windows call that leaves the home, makes moves
// folder moves that may fail, then pads relative appends before last.
func gap1281PaddedCall(cmd bool, moves, pads int, last string) string {
	const home = `C:\Users\alice`
	separator, text := "; ", "Set-Location "+home+"; "
	if cmd {
		separator, text = " & ", "cd /d "+home+" & "
	}
	for i := 1; i <= moves; i++ {
		if cmd {
			text += fmt.Sprintf(`cd /d C:\nx-g1281-%d & `, i)
		} else {
			text += fmt.Sprintf(`cd C:\nx-g1281-%d; `, i)
		}
	}
	parts := make([]string, 0, pads+1)
	for i := 0; i < pads; i++ {
		parts = append(parts, fmt.Sprintf("type nul >> p%d.txt", i))
	}
	return text + strings.Join(append(parts, last), separator)
}

// rel-1-0-10:GAP-1281: past maxSimpleWindowsOtherReadings (GAP-1228) a
// statement after folder moves that may fail kept only an UnresolvedFolder
// reading with no folder, so its reading in the home (where the moves leave
// the shell when they fail) was gone. The reading now carries the folders
// it was not read in, the home among them, for the gateway to read the
// statement where its operand may name a protected file. Below the cap the
// statement keeps its named readings and no reading carries capped folders.
func TestGAP1281CappedWindowsReadingKeepsTheFoldersItWasNotReadIn(t *testing.T) {
	const home, attack = `C:\Users\alice`, `type nul >> .defenseclaw\config.yaml`
	for _, cmd := range []bool{false, true} {
		dialect := DialectPowerShell
		if cmd {
			dialect = DialectCMD
		}
		for _, row := range []struct {
			moves, pads int
			capped      bool
		}{{2, 0, false}, {2, 30, false}, {2, 64, true}, {2, 65, true}, {7, 17, false}, {7, 18, true}, {7, 40, true}} {
			input := Input{Tool: "shell", Command: gap1281PaddedCall(cmd, row.moves, row.pads, attack), CWD: home + `\project`,
				ActiveHome: home, DialectHint: dialect}
			var inHome, carried bool
			for _, simple := range SimpleCommands(input, Analyze(input)) {
				if simple.EvaluationFailure != "" {
					t.Fatalf("cmd=%v k=%d n=%d: evaluation failure %q", cmd, row.moves, row.pads, simple.EvaluationFailure)
				}
				folders := simple.CappedFolders()
				if len(folders) != 0 && !simple.UnresolvedFolder {
					t.Errorf("cmd=%v k=%d n=%d: capped folders on a reading in a folder (%q)", cmd, row.moves, row.pads, simple.CWD)
				}
				if strings.TrimSpace(simple.Text) != attack {
					continue
				}
				isHome := func(folder string) bool {
					return strings.EqualFold(strings.ReplaceAll(folder, `\`, "/"), "C:/Users/alice")
				}
				inHome = inHome || simple.OtherFolder && isHome(simple.CWD)
				carried = carried || slices.ContainsFunc(folders, isHome)
			}
			if row.capped && (inHome || !carried) {
				t.Errorf("cmd=%v k=%d n=%d (past the cap): home reading %v, home carried by the unresolved reading %v; want false, true",
					cmd, row.moves, row.pads, inHome, carried)
			}
			if !row.capped && (!inHome || carried) {
				t.Errorf("cmd=%v k=%d n=%d (below the cap): home reading %v, carried %v; want true, false", cmd, row.moves, row.pads, inHome, carried)
			}
		}
	}
}
