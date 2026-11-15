// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"slices"
	"strings"
	"testing"
)

// TestWindowsLauncherShapesKeepTheFixtureVerdict wraps a toolcall fixture that
// fires bare in the shapes a script can be embedded in, read structurally on
// the psparse tree (rel-1-0-10:GAP-0348, review F7): a launcher inside a branch,
// a loop, a try, a function, a pipeline stage, an assignment or a
// sub-expression; a -Command script block; a built script block; a
// Start-Process -ArgumentList; and cmd //c under Git Bash.
func TestWindowsLauncherShapesKeepTheFixtureVerdict(t *testing.T) {
	const rule = "persistence.ssh_authorized_keys_command"
	const command = `Add-Content -Path C:\Users\alice\.ssh\authorized_keys -Value k`
	quote := func(text string) string { return "'" + strings.ReplaceAll(text, "'", "''") + "'" }
	launch := "powershell -NoProfile -Command " + quote(command)
	shapes := []struct{ name, tool, text string }{
		{"in a branch", "PowerShell", "if ($true) { " + launch + " }"},
		{"in an else", "PowerShell", "if ($false) { Get-Date } else { " + launch + " }"},
		{"in a loop", "PowerShell", "foreach ($i in 1..2) { " + launch + " }"},
		{"in a try", "PowerShell", "try { " + launch + " } catch { Get-Date }"},
		{"in a function", "PowerShell", "function f { " + launch + " }; f"},
		{"in a pipeline stage", "PowerShell", "Get-Date | ForEach-Object { " + launch + " }"},
		{"in an assignment", "PowerShell", "$r = " + launch},
		{"in a sub-expression", "PowerShell", "Write-Output $(" + launch + ")"},
		{"as a script block argument", "PowerShell", "powershell -NoProfile -Command { " + command + " }"},
		{"built script block", "PowerShell", "[scriptblock]::Create(" + quote(command) + ").Invoke()"},
		{"through Start-Process", "PowerShell", "Start-Process powershell -ArgumentList '-NoProfile','-Command'," + quote(command)},
		{"cmd //c under Git Bash", "Bash", "cmd //c \"powershell -NoProfile -Command " + quote(command) + "\""},
	}
	for _, pack := range []string{"default", "strict"} {
		for _, shape := range shapes {
			t.Run(pack+"/"+shape.name, func(t *testing.T) {
				findings := windowsBoundsFindings(t, pack, shape.tool, shape.text, `C:\Users\alice`, pack == "strict")
				if !slices.ContainsFunc(findings, func(f RuleFinding) bool { return f.RuleID == rule }) {
					t.Fatalf("no %s finding: %v", rule, FindingStrings(findings))
				}
			})
		}
	}
}
