// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"slices"
	"strings"
	"testing"
)

// TestGAP1150WindowsStatementAfterAFailedMoveIsReadInEveryFolder pins
// rel-1-0-10:GAP-1150, the PowerShell and CMD side of GAP-0133: a
// Set-Location, cd, chdir, Push-Location or pushd that fails (a missing
// folder) is not a terminating error, and a failed CMD cd does not stop the
// command after & or a newline, so the statement after it runs where the
// shell stood. The per-statement split reads such a statement in the folder
// the moves lead to (CWD, the reading of before) AND in every folder it may
// run in after a move that failed (OtherFolder). The statement right after
// `move &&` runs in the moved folder alone. The rows are spelled from the
// same parts as the gateway rows of this gap; the state file is not opened.
func TestGAP1150WindowsStatementAfterAFailedMoveIsReadInEveryFolder(t *testing.T) {
	const home = `C:\Users\alice`
	const project = home + `\project`
	const missing = `C:\nonexistent-gap1150`
	rel := `.defenseclaw\config.yaml`
	write := "type nul >> " + rel
	type row struct {
		id, dialect, command, statement string
		// folders are the folders the statement must be read in.
		folders []string
		// not are folders the statement must not be read in.
		not []string
	}
	ps, cmd := string(DialectPowerShell), string(DialectCMD)
	rows := []row{
		{"set-location-then-cd", ps, "Set-Location " + home + "; cd " + missing + "; " + write, write,
			[]string{missing, home, project}, nil},
		{"newlines", ps, "Set-Location " + home + "\ncd " + missing + "\n" + write, write,
			[]string{missing, home, project}, nil},
		{"silent", ps, "Set-Location " + home + "; Set-Location -Path " + missing + " -ErrorAction SilentlyContinue; " + write, write,
			[]string{home, project}, nil},
		{"push-location", ps, "Set-Location " + home + "; Push-Location " + missing + "; " + write, write,
			[]string{missing, home, project}, nil},
		{"literal-path", ps, "Set-Location -LiteralPath " + home + "; Set-Location -LiteralPath " + missing + "; " + write, write,
			[]string{missing, home, project}, nil},
		{"chdir", ps, "chdir " + home + "; chdir " + missing + "; " + write, write,
			[]string{missing, home, project}, nil},
		{"add-content", ps, "Set-Location " + home + "; cd " + missing + "; Add-Content -Path " + rel + " -Value x",
			"Add-Content -Path " + rel + " -Value x", []string{missing, home, project}, nil},
		// After `move &&` the right side runs only where the move worked.
		{"and-right-side", ps, "Set-Location " + home + " && " + write, write, []string{home}, []string{project}},
		// The statement after the && list may run where the move failed.
		{"after-and-list", ps, "cd " + missing + " && Write-Output x; " + write, write, []string{missing, project}, nil},
		{"cmd-and-chain", cmd, "cd /d " + home + " & cd /d " + missing + " & " + write, write,
			[]string{missing, home, project}, nil},
		{"pushd", cmd, "pushd " + home + " & pushd " + missing + " & " + write, write,
			[]string{missing, home, project}, nil},
		// A statement with no relative operand has no other reading.
		{"absolute-operand", ps, "cd " + missing + "; type nul >> " + home + `\` + rel, "type nul >> " + home + `\` + rel,
			[]string{missing}, []string{project}},
	}
	for _, r := range rows {
		t.Run(r.id, func(t *testing.T) {
			input := Input{Tool: "shell", Command: r.command, CWD: project, ActiveHome: home, DialectHint: Dialect(r.dialect)}
			simples := SimpleCommands(input, Analyze(input))
			var folders []string
			for _, simple := range simples {
				if simple.EvaluationFailure == "" && strings.TrimSpace(simple.Text) == r.statement {
					folders = append(folders, strings.ReplaceAll(simple.CWD, "/", `\`))
				}
			}
			for _, want := range r.folders {
				if !slices.ContainsFunc(folders, func(have string) bool { return strings.EqualFold(have, want) }) {
					t.Errorf("%q is not read in %s: folders %q (%+v)", r.statement, want, folders, simples)
				}
			}
			for _, unwanted := range r.not {
				if slices.ContainsFunc(folders, func(have string) bool { return strings.EqualFold(have, unwanted) }) {
					t.Errorf("%q is read in %s, where it does not run: folders %q", r.statement, unwanted, folders)
				}
			}
		})
	}
	// A call placed nowhere (no folder of its own) keeps the one reading:
	// the hook client keys its facts by it.
	input := Input{Tool: "shell", Command: "cd " + missing + "; " + write, ActiveHome: home, DialectHint: DialectPowerShell}
	for _, simple := range SimpleCommands(input, Analyze(input)) {
		if simple.OtherFolder {
			t.Errorf("a call with no folder got another-folder reading %+v", simple)
		}
	}
}
