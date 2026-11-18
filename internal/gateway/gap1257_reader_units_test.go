// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// The GAP-1257 reader units: what kind of receiver each FileInfo expression
// is, which uses of a variable may bind it, and the folder twin of a path.
func TestGAP1257ReaderUnits(t *testing.T) {
	for _, row := range []struct {
		text string
		kind psFileInfoKind
	}{
		{`Get-ChildItem 'd'`, psFileInfoChildren},
		{`ls -LiteralPath 'd'`, psFileInfoChildren},
		{`Get-Item 'd'`, psFileInfoItem},
		{`[IO.FileInfo]::new('f')`, psFileInfoFile},
		{`New-Object System.IO.FileInfo('f')`, psFileInfoFile},
	} {
		if got := psFileInfoExpression(row.text, &psBudget{}); got.param == "" || got.kind != row.kind {
			t.Errorf("psFileInfoExpression(%s) = %+v, want kind %d", row.text, got, row.kind)
		}
	}
	for _, row := range []struct {
		text        string
		reads       bool
		assignments int
		rebinds     bool
	}{
		{`$f = x; $f.m()`, true, 1, false},
		{`[t]$f = x; $f.m(); $f.n`, true, 1, false},
		{`$f = x; { $f = y }; $f.m()`, true, 2, false},
		{`$f = x; $f += y`, true, 1, true},
		{`$f = x; $g, $f = y`, true, 2, false},
		{`$f, $g = y`, true, 0, true},
		{`foreach ($f in $x) { }`, true, 0, true},
		{`$f = x; set-variable f y`, true, 1, true},
		{`$f = x; ${f}.m()`, true, 1, true},
		{`$f = x; w $f`, true, 1, true},
		{`$f = x; w $f`, false, 1, false},
		{`$f = x; '{0}' -f 1; get-item d/f/f.txt`, true, 1, false},
		{`$fa = x; $af.m(); $f_x`, true, 0, false},
	} {
		assignments, rebinds := psVariableUses(row.text, "f", row.reads)
		if assignments != row.assignments || rebinds != row.rebinds {
			t.Errorf("psVariableUses(%s, reads=%v) = %d %v, want %d %v", row.text, row.reads, assignments, rebinds, row.assignments, row.rebinds)
		}
	}
	for _, row := range []struct{ param, want string }{
		{`-LiteralPath 'a/b'`, `Remove-Item -LiteralPath 'a/b' -Recurse -Force`},
		{`-Path 'a/b'`, `Remove-Item -Path 'a/b' -Recurse -Force`},
		{`-Path 'a/b/*.json'`, `Remove-Item -Path 'a/b' -Recurse -Force`},
		{`-Path "a\b?\c"`, `Remove-Item -Path "a" -Recurse -Force`},
		{`-Path *.log`, ``},
		{`-Path /*`, ``},
	} {
		if got := psFolderTwin(row.param, ""); got != row.want {
			t.Errorf("psFolderTwin(%s) = %q, want %q", row.param, got, row.want)
		}
	}
}
