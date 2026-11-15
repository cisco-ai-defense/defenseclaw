// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestPowerShellTopLevelStatements(t *testing.T) {
	for _, tc := range []struct {
		command string
		want    []string
	}{
		{"a; b\nc | d", []string{"a", "b", "c | d"}},
		{"$x = & git rev-parse HEAD\n$y = 1", []string{"$x = & git rev-parse HEAD", "$y = 1"}},
		{"Write-Output $(\nGet-Date\n)\nb", []string{"Write-Output $(\nGet-Date\n)", "b"}},
		{"if ($a) {\n x\n y\n}\nz", []string{"if ($a) {\n x\n y\n}", "z"}},
		{"Write-Output \"a;b\" # c; d\ne", []string{"Write-Output \"a;b\" # c; d", "e"}},
		{"a |\nb\nc", []string{"a |\nb", "c"}},
		{"a && b; c", []string{"a && b", "c"}},
	} {
		got, ok := powerShellTopLevelStatements(tc.command, maxStatementsAlone)
		if !ok || !slices.Equal(got, tc.want) {
			t.Errorf("%q: got %q ok=%t, want %q", tc.command, got, ok, tc.want)
		}
	}
	if _, ok := powerShellTopLevelStatements(strings.Repeat("a\n", maxStatementsAlone+1), maxStatementsAlone); ok {
		t.Error("a call over the statement budget was split")
	}
}

// TestPowerShellCappedRuns: a capped reading of ordinary lines with no
// statement that reads complete alone has no run; one whose readable
// statements fit under the cap has one run of them; a left-out statement that
// may change the next ones means no run.
func TestPowerShellCappedRuns(t *testing.T) {
	filler := make([]string, 100)
	for i := range filler {
		filler[i] = fmt.Sprintf("$o%d = & git rev-parse HEAD", i)
	}
	input := func(lines ...string) (Input, Facts) {
		in := Input{Tool: "PowerShell", Command: strings.Join(lines, "\n"), CWD: `C:\repo`, DialectHint: DialectPowerShell}
		return in, Analyze(in)
	}
	in, facts := input(filler...)
	if facts.Parse.Status != StatusLimitExceeded {
		t.Fatalf("100 ordinary lines: status %s, want a capped reading", facts.Parse.Status)
	}
	if runs := PowerShellCappedRuns(in, facts); len(runs) != 0 {
		t.Errorf("100 ordinary lines: %d runs, want none", len(runs))
	}
	in, facts = input(append([]string{"Get-ChildItem C:\\repo"}, filler...)...)
	runs := PowerShellCappedRuns(in, facts)
	if len(runs) != 1 || runs[0].Command != "Get-ChildItem C:\\repo" || runs[0].DialectHint != DialectPowerShell {
		t.Errorf("a readable statement and 100 ordinary lines: runs %+v, want the one readable statement", runs)
	}
	in, facts = input(append([]string{"Set-Location $env:TEMP", "Get-ChildItem C:\\repo"}, filler...)...)
	if runs := PowerShellCappedRuns(in, facts); len(runs) != 0 && facts.Parse.Status == StatusLimitExceeded {
		// Set-Location reads complete, so it is kept, not left out: the run
		// holds both statements in order.
		if !strings.HasPrefix(runs[0].Command, "Set-Location") {
			t.Errorf("Set-Location first: runs %+v, want it kept in order", runs)
		}
	}
	in, facts = input(append([]string{"Set-Location (Get-Random)", "Get-ChildItem C:\\repo"}, filler...)...)
	if runs := PowerShellCappedRuns(in, facts); len(runs) != 0 {
		t.Errorf("an unreadable location change: %d runs, want none", len(runs))
	}
	in, facts = input("Get-ChildItem C:\\repo", "Get-Date")
	if runs := PowerShellCappedRuns(in, facts); runs != nil {
		t.Errorf("a complete reading: runs %+v, want none", runs)
	}
}
