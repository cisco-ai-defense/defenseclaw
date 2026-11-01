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
	} {
		if got := PowerShellStatementsOverBudget(tc.command); got != tc.over {
			t.Errorf("%s (%d bytes): over budget %t, want %t", tc.name, len(tc.command), got, tc.over)
		}
	}
}
