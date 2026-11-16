// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"
	"testing"
)

// These rows follow PowerShell 7 Parser::ParseInput: executable rows expose
// the Remove-Item tail, while the controls comment it out.
func TestGAP0451PowerShellStatementStartInsideValues(t *testing.T) {
	const tail = `Remove-Item -Recurse -Force C:\dccert-block-marker`
	type testRow struct {
		name, prefix string
		executable   bool
	}
	rows := []testRow{
		{"subexpression path", `Write-Output $(.\a[1]#); `, true},
		{"subexpression glued double quote", `Write-Output $(a"b"#); `, true},
		{"array glued double quote", `Write-Output @(a"b"#); `, true},
		{"assignment subexpression", `$x = $(a"b"#); `, true},
		{"paren glued double quote", `Write-Output (a"b"#); `, true},
		{"paren path", `(.\a[1]#); `, true},
		{"subexpression command", `Write-Output $(Write-Output a"b"#); `, true},
		{"call subexpression", `& $(a"b"#); `, true},
		{"interpolated subexpression", `Write-Output "$(a"b"#)"; `, true},
		{"subexpression glued single quote", `Write-Output $(a'b'#); `, true},
		{"subexpression block marker", `Write-Output $(.\a[1]<#x#>); `, true},
		{"scriptblock path", `& {.\a[1]#}; `, true},
		{"subexpression type comment", "Write-Output $([int]#\n); ", true},
		{"type expression comment", `[int]#; `, false},
		{"single quoted comment", `Write-Output 'a'#; `, false},
		{"double quoted comment", `"a"#; `, false},
	}
	// Parser::ParseInput sees each glued word as a command in all three
	// value frames; its closing # is part of the command word.
	for _, frame := range []struct{ name, prefix string }{
		{"subexpression", `Write-Output $(`},
		{"array", `Write-Output @(`},
		{"parenthesized", `Write-Output (`},
	} {
		for _, word := range []string{"/a", "-a", "*a", "%a", "!a", "?a", "=a", "1a", "0x1"} {
			rows = append(rows, testRow{frame.name + " " + word, frame.prefix + word + `"b"#); `, true})
		}
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			command := row.prefix + tail
			out := parsePowerShell(command, 1, 0)
			if got := hasExecutable(out.commands, "remove-item"); got != row.executable {
				t.Errorf("reader sees tail=%t, want %t: status=%s commands=%#v", got, row.executable, out.status, out.commands)
			}
			count, _ := powerShellStatements(command, 128)
			if row.executable && count < 2 || !row.executable && count != 1 {
				t.Errorf("budget count=%d, executable=%t", count, row.executable)
			}
			input := Input{Tool: "PowerShell", Command: command, DialectHint: DialectPowerShell}
			seen := false
			for _, simple := range SimpleCommands(input, Analyze(input)) {
				seen = seen || strings.Contains(simple.Text, "Remove-Item")
			}
			if seen != row.executable {
				t.Errorf("splitter sees tail=%t, want %t", seen, row.executable)
			}
		})
	}
}
