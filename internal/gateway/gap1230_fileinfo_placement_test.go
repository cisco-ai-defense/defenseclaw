// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// The reader's placements of the GAP-1230 receivers, unit by unit: what each
// FileInfo expression evaluates to, and the typed assignment.
func TestGAP1230FileInfoPlacement(t *testing.T) {
	for _, row := range []struct{ text, want string }{
		{`Get-ChildItem 'f'`, `-Path 'f'`},
		{`dir -LiteralPath 'f'`, `-LiteralPath 'f'`},
		{`gci 'f' -File`, `-Path 'f'`},
		{`Get-ChildItem 'd' -Filter 'f'`, ``},
		{`Get-ChildItem -Recurse 'd'`, ``},
		{`New-Object System.IO.FileInfo('f')`, `-LiteralPath 'f'`},
		{`New-Object -TypeName IO.FileInfo -ArgumentList 'f'`, `-LiteralPath 'f'`},
		{`New-Object IO.StreamReader('f')`, ``},
		{`[IO.FileInfo]::new`, ``},
		{`[IO.FileInfo]::new('f')`, `-LiteralPath 'f'`},
	} {
		if got := psFileInfoExpression(row.text, &psBudget{}); got != row.want {
			t.Errorf("psFileInfoExpression(%s) = %q, want %q", row.text, got, row.want)
		}
	}
	for _, row := range []struct{ text, variable, typeName, rest string }{
		{`$f = 'x'`, "f", "", " 'x'"},
		{`[IO.FileInfo]$F = 'x'`, "f", "[io.fileinfo]", " 'x'"},
		{`[ValidateNotNull()][System.IO.FileInfo] $f = 'x'`, "f", "[system.io.fileinfo]", " 'x'"},
		{`[IO.File]::Open('x')`, "", "", `[IO.File]::Open('x')`},
		{`[void]$f.Open('x')`, "", "", `[void]$f.Open('x')`},
		{`$f == 'x'`, "", "", `$f == 'x'`},
	} {
		variable, typeName, rest := psTypedAssignment(row.text)
		if variable != row.variable || typeName != row.typeName || rest != row.rest {
			t.Errorf("psTypedAssignment(%s) = %q %q %q, want %q %q %q", row.text, variable, typeName, rest, row.variable, row.typeName, row.rest)
		}
	}
}
