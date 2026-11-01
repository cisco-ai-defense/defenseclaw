// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"fmt"
	"strings"
	"testing"
)

// TestPowerShellStatementsOverBudget is rel-1-0-6:GAP-0318: the PowerShell
// split's statement budget, counted past the Windows lexer's token bound,
// with quoted and here-string separators not counted.
func TestPowerShellStatementsOverBudget(t *testing.T) {
	statements := func(n int, form string) string {
		parts := make([]string, n)
		for i := range parts {
			parts[i] = fmt.Sprintf(form, i)
		}
		return strings.Join(parts, "; ")
	}
	for _, tc := range []struct {
		name    string
		command string
		over    bool
	}{
		{"128 statements", statements(128, "echo x%d"), false},
		{"129 statements", statements(129, "echo x%d"), true},
		{"3000 writes past the token bound", statements(3000, "echo line%d >> notes.txt"), true},
		{"129 pipeline stages", "Get-Content a.txt" + strings.Repeat(" | Out-String", 128), true},
		{"129 lines", statements(129, "Write-Output %d") + "\n", true},
		{"separators in a quoted string", "Write-Output '" + strings.Repeat("a; b | c; ", 400) + "'", false},
		{"lines of a here-string", "Set-Content notes.txt -Value @'\n" + strings.Repeat("line; one | two\n", 3000) + "'@", false},
		{"empty", "", false},
		// rel-1-0-6:GAP-0331: a one-token prefix that stops the Windows
		// lexer does not hide the statements after it.
		{"subexpression prefix, 100", "$x = $(Get-Date); " + statements(100, "echo x%d"), false},
		{"subexpression prefix, 3000", "$x = $(Get-Date); " + statements(3000, "echo x%d"), true},
		{"array prefix, 3000", "$a = @(1, 2); " + statements(3000, "echo x%d"), true},
		{"hashtable prefix, 3000", "$h = @{ a = 1; b = 2 }; " + statements(3000, "echo x%d"), true},
		{"braced variable prefix, 3000", "${x} = 1; " + statements(3000, "echo x%d"), true},
		{"here-string prefix, 100", "$t = @'\nbody; | ;\n'@\n" + statements(100, "echo x%d"), false},
		{"here-string prefix, 3000", "$t = @'\nbody; | ;\n'@\n" + statements(3000, "echo x%d"), true},
		{"statements inside a subexpression", "Write-Output $(" + statements(200, "echo x%d") + ")", true},
		{"statements inside a script block", "& { " + statements(200, "echo x%d") + " }", true},
		{"statements in an expandable string subexpression", "Write-Output \"$(" + statements(200, "echo x%d") + ")\"", true},
		{"hashtable entries", "$h = @{ " + statements(300, "k%d = 1") + " }", false},
		{"block comment", "<# " + strings.Repeat("a; b | c\n", 300) + "#> Get-Date", false},
		{"line comments", strings.Repeat("# a; b | c\n", 300) + "Get-Date", false},
		{"CRLF lines", strings.Repeat("Get-Date\r\n", 129), true},
		{"smart-quoted separators", "Write-Output \u2018" + strings.Repeat("a; b | ", 300) + "\u2019", false},
		{"multi-line if blocks", strings.Repeat("if ($x) {\n  Get-Date\n}\n", 60), false},
	} {
		if got := PowerShellStatementsOverBudget(tc.command); got != tc.over {
			t.Errorf("%s (%d bytes): over budget %t, want %t", tc.name, len(tc.command), got, tc.over)
		}
	}
}

// TestPowerShellReadingStopsEarly: the constructs that stop the Windows
// lexer, outside quotes (rel-1-0-6:GAP-0331).
func TestPowerShellReadingStopsEarly(t *testing.T) {
	for _, tc := range []struct {
		command string
		stops   bool
	}{
		{"$x = $(Get-Date); Write-Output $x", true},
		{"$a = @(1, 2)", true},
		{"$h = @{ a = 1 }", true},
		{"${x} = 1", true},
		{"$t = @'\nbody\n'@", true},
		{"cmd /c dir --% /s", true},
		{`Write-Host "defenseclaw step 1"; Get-Content $HOME\.defenseclaw\config.yaml`, false},
		{"Write-Output '$(not a subexpression)'", false},
		{"Get-ChildItem | Select-Object -First 5", false},
	} {
		if got := PowerShellReadingStopsEarly(tc.command); got != tc.stops {
			t.Errorf("%q: stops early %t, want %t", tc.command, got, tc.stops)
		}
	}
}
