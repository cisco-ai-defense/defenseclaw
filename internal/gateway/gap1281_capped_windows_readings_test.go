// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// rel-1-0-10:GAP-1281: a padded Windows call past the reading cap reads a
// statement that may name a protected file in the folders the cap left out
// (withCappedWindowsReadings), so the relative write of the DefenseClaw
// config is read in the home again, where its rule proves it. A benign
// padded call adds no reading: the cap keeps its cost (GAP-1228, GAP-1293).
// The hook-route rows run on native Windows
// (TestGAP1228PaddedWindowsCallAfterMovesThatMayFailKeepsItsReadingsFiveTiers).
func TestGAP1281CappedWindowsStatementIsReadWhereItMayNameAProtectedFile(t *testing.T) {
	const home = `C:\Users\alice`
	build := func(cmd bool, moves, pads int, last string) string {
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
	for _, cmd := range []bool{false, true} {
		dialect := actionfacts.DialectPowerShell
		if cmd {
			dialect = actionfacts.DialectCMD
		}
		for _, row := range []struct {
			id          string
			moves, pads int
			last        string
			// homeReading: the last statement is read in the home.
			homeReading bool
		}{
			{"atk-k2-n64", 2, 64, `type nul >> .defenseclaw\config.yaml`, true},
			{"atk-k7-n18", 7, 18, `type nul >> .defenseclaw\config.yaml`, true},
			{"atk-k7-n40-ssh", 7, 40, `type nul >> .ssh\authorized_keys`, true},
			{"ben-k7-n40", 7, 40, "type nul >> notes.txt", false},
			{"ben-k2-n100", 2, 100, "type nul >> notes.txt", false},
		} {
			input := actionfacts.Input{Tool: "shell", Command: build(cmd, row.moves, row.pads, row.last), CWD: home + `\project`,
				ActiveHome: home, DialectHint: dialect}
			simples := actionfacts.SimpleCommands(input, actionfacts.Analyze(input))
			read := withCappedWindowsReadings(trustedActionRequest{Input: input}, simples)
			if !row.homeReading {
				if len(read) != len(simples) {
					t.Errorf("cmd=%v %s: %d readings, want the %d of the reader (benign padding adds none)", cmd, row.id, len(read), len(simples))
				}
				continue
			}
			inHome := false
			for _, simple := range read {
				if strings.TrimSpace(simple.Text) == row.last && simple.OtherFolder && !simple.UnresolvedFolder &&
					strings.EqualFold(strings.ReplaceAll(simple.CWD, `\`, "/"), "C:/Users/alice") {
					inHome = true
				}
			}
			if !inHome {
				t.Errorf("cmd=%v %s: the last statement is not read in the home (%d readings, reader %d)", cmd, row.id, len(read), len(simples))
			}
			if len(read) > len(simples)+row.moves+1 {
				t.Errorf("cmd=%v %s: %d readings for a reader of %d: more than one statement was read again", cmd, row.id, len(read), len(simples))
			}
		}
	}
}
