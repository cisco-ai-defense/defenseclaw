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
		// Review R2-4: a line end inside a bare ( ) or after a trailing
		// comma continues the statement.
		{"multi-line array with trailing commas", "$list = @(\n" + strings.ReplaceAll(statements(300, "  'item%d',"), "; ", "\n") + "\n  'last'\n)\nWrite-Output $list", false},
		{"multi-line param block", "param(\n" + strings.ReplaceAll(statements(200, "  [string]$p%d,"), "; ", "\n") + "\n  [int]$last\n)\nWrite-Output $(1)", false},
		{"comma continuation at top level", "$a = 1,\n" + strings.ReplaceAll(statements(200, "%d,"), "; ", "\n") + "\n2; $x = $(1)", false},
		{"multi-line hashtable", "$h = @{\n" + strings.ReplaceAll(statements(300, "  k%d = 1"), "; ", "\n") + "\n}\nWrite-Output $h", false},
		{"PowerShell 7 background chain", strings.ReplaceAll(statements(200, "Write-Output %d"), "; ", " & "), true},
		{"call operator at each statement start", statements(129, "& git status %d"), true},
		{"redirect 2>&1 is no separator", strings.Repeat("Write-Output 1 2>&1 ", 200), false},
		// Review r3: a comma inside a line comment does not continue the
		// line (finding 1); a comma before the comment does.
		{"line comments that end in a comma", strings.ReplaceAll(statements(200, "Write-Output %d # note,"), "; ", "\n"), true},
		{"array items with a comment after the comma", "$list = @(\n" + strings.ReplaceAll(statements(300, "  'item%d', # note"), "; ", "\n") + "\n  'last'\n)", false},
		// The call operator after an assignment ends no statement
		// (finding 2).
		{"assigned call operator, 70 lines", strings.ReplaceAll(statements(70, "$o%d = & git rev-parse HEAD"), "; ", "\n"), false},
		{"assigned call operator, 128 lines", strings.ReplaceAll(statements(128, "$o%d = & git rev-parse HEAD"), "; ", "\n"), false},
		{"assigned call operator, 129 lines", strings.ReplaceAll(statements(129, "$o%d = & git rev-parse HEAD"), "; ", "\n"), true},
		{"quoted call target after an assignment", strings.ReplaceAll(statements(100, "$o%d = & 'git' status"), "; ", "\n"), false},
		// Line ends inside a bare ( ) with no commas: a multi-line
		// condition is one statement (review r3 finding 4, mutation MH).
		{"multi-line condition in a bare ( )", "if (\n" + strings.ReplaceAll(statements(140, "$a%d -eq 1 -or"), "; ", "\n") + "\n$true) { Get-Date }", false},
		// Block comments are not statements (item 5c).
		{"block comments ending each line", strings.ReplaceAll(statements(200, "Write-Output %d <# , #>"), "; ", "\n"), true},
		{"block comments on 100 lines", strings.ReplaceAll(statements(100, "Write-Output %d <# , ; | #>"), "; ", "\n"), false},
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
		{"& { Get-Date }; Write-Output 1", true},
		{"& $env:ComSpec /c ver", true},
		{"Write-Output 1 2>&1", false},
		{`Write-Host "defenseclaw step 1"; Get-Content $HOME\.defenseclaw\config.yaml`, false},
		{"Write-Output '$(not a subexpression)'", false},
		{"Get-ChildItem | Select-Object -First 5", false},
	} {
		if got := PowerShellReadingStopsEarly(tc.command); got != tc.stops {
			t.Errorf("%q: stops early %t, want %t", tc.command, got, tc.stops)
		}
	}
}
