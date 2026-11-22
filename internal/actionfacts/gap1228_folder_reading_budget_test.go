// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"fmt"
	"strings"
	"testing"
)

// TestGAP1228ReadingsInOtherFoldersNeverMakeTheCallOverBudget pins
// rel-1-0-10:GAP-1228 (review round 1 of s7/cdcand): the readings of a
// statement in the other folders it may run in, after folder moves that may
// fail (GAP-1150 for PowerShell and CMD, GAP-1144 for a POSIX shell body),
// came out of the evaluation budget of the call, so a padded call the base
// reads statement by statement went to the whole-call limit (no statement
// judged, the unknown tier) once those readings passed it (the hook-route
// rows are TestGAP1228PaddedWindowsCallAfterMovesThatMayFailKeepsItsReadingsFiveTiers). The statements
// of the call keep the budget they have on rel; the readings in other
// folders come on top of it, and past the budget a statement is read once
// more as in a folder the walk does not give (UnresolvedFolder). Every
// statement of the call keeps its own reading.
func TestGAP1228ReadingsInOtherFoldersNeverMakeTheCallOverBudget(t *testing.T) {
	const home = `C:\Users\alice`
	cwd := home + `\project`
	pad := func(prefix, write string, n int) []string {
		parts := make([]string, n)
		for i := range parts {
			parts[i] = fmt.Sprintf("%s %s%d.txt", write, prefix, i)
		}
		return parts
	}
	type row struct {
		id, command string
		dialect     Dialect
		cwd, home   string
		// statements are the statements every one of which must keep its
		// reading in the folder the walk gives it.
		statements []string
	}
	var rows []row
	psMoves, cmdMoves := "", ""
	for i := 1; i <= 7; i++ {
		psMoves += fmt.Sprintf(`cd C:\nx-gap1228-%d; `, i)
		cmdMoves += fmt.Sprintf(`cd /d C:\nx-gap1228-%d & `, i)
	}
	key := `Add-Content -Path C:\Users\alice\.ssh\authorized_keys -Value k`
	statements := append(append(append([]string{}, pad("a", "type nul >>", 35)...), key), pad("b", "type nul >>", 35)...)
	rows = append(rows, row{"ps-moves-pad70", psMoves + strings.Join(statements, "; "), DialectPowerShell, cwd, home, statements})
	benign := pad("a", "type nul >>", 70)
	rows = append(rows, row{"ps-moves-pad70-benign", psMoves + strings.Join(benign, "; "), DialectPowerShell, cwd, home, benign})
	cmdPad := pad("a", "type nul >>", 70)
	rows = append(rows, row{"cmd-moves-pad70", cmdMoves + strings.Join(cmdPad, " & "), DialectCMD, cwd, home, cmdPad})
	// A POSIX shell body after a cd chain is read in each folder the chain
	// may leave (GAP-1144): three padded bodies, the key write in the
	// middle of the second. (On the hook route the gateway statement
	// budget of 128 stops a call this long first.)
	touches := pad("a", "touch", 300)
	for i := range touches {
		touches[i] = strings.TrimSuffix(touches[i], ".txt")
	}
	second := append(append(append([]string{}, touches[100:150]...), "echo k >> /home/alice/.ssh/authorized_keys"), touches[150:200]...)
	posixBodies := append(append(append([]string{}, touches[:100]...), second...), touches[200:]...)
	rows = append(rows, row{"posix-chain-three-bodies", "cd /srv/a || cd /srv/b && sh -c '" + strings.Join(touches[:100], "; ") +
		"'; sh -c '" + strings.Join(second, "; ") + "'; sh -c '" + strings.Join(touches[200:], "; ") + "'",
		DialectPOSIX, "/home/alice/project", "/home/alice", posixBodies})
	for _, r := range rows {
		t.Run(r.id, func(t *testing.T) {
			input := Input{Tool: "Bash", Command: r.command, CWD: r.cwd, ActiveHome: r.home, DialectHint: r.dialect}
			if r.dialect != DialectPOSIX {
				input.Tool = "shell"
			}
			simples := SimpleCommands(input, Analyze(input))
			read := map[string]bool{}
			other, unresolved := 0, 0
			for _, simple := range simples {
				if simple.EvaluationFailure == "limit" {
					t.Fatalf("the call went to the whole-call limit (%d readings)", len(simples))
				}
				if simple.OtherFolder {
					other++
					if simple.UnresolvedFolder {
						unresolved++
					}
					continue
				}
				read[strings.TrimSpace(simple.Text)] = true
			}
			for _, statement := range r.statements {
				if !read[statement] {
					t.Errorf("the statement %q has no reading of its own", statement)
				}
			}
			if other == 0 || unresolved == 0 {
				t.Errorf("readings in other folders %d, as in a folder the walk does not give %d: want both", other, unresolved)
			}
			if len(simples) > 3*maxSimpleEvaluations {
				t.Errorf("%d readings: over three times the evaluation budget", len(simples))
			}
		})
	}
}
