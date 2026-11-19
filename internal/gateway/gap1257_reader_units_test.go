// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// The GAP-1257 reader units: what kind of receiver each FileInfo expression
// is, the paths of a path array (GAP-1277), which uses of a variable may
// bind it (a plain read does not, GAP-1278), and the folder twin of a path.
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
		if got := psFileInfoExpression(row.text, &psBudget{}); !got.placed() || got.kind != row.kind {
			t.Errorf("psFileInfoExpression(%s) = %+v, want kind %d", row.text, got, row.kind)
		}
	}
	for _, row := range []struct {
		text  string
		count int
	}{
		{`Get-Item 'a'`, 1},
		{`Get-Item 'a','b'`, 2},
		{`gi 'a', 'b' -Force`, 2},
		{`Get-Item -LiteralPath 'a','b'`, 2},
		{`Get-ChildItem a,b`, 2},
		{`Get-Item 'a',$env:x[0]`, 0},
		{`Get-Item 'a',(x)`, 0},
		{`Get-Item 'a', 'b' 'c'`, 0},
	} {
		if got := psFileInfoExpression(row.text, &psBudget{}); len(got.params) != row.count {
			t.Errorf("psFileInfoExpression(%s) = %+v, want %d paths", row.text, got, row.count)
		}
	}
	for _, row := range []struct {
		text        string
		assignments int
		rebinds     bool
	}{
		{`$f = x; $f.m()`, 1, false},
		{`[t]$f = x; $f.m(); $f.n`, 1, false},
		{`$f = x; { $f = y }; $f.m()`, 2, false},
		{`$f = x; $f += y`, 1, true},
		{`$f = x; $g, $f = y`, 2, false},
		{`$f, $g = y`, 0, true},
		{`foreach ($f in $x) { }`, 0, true},
		{`$f = x; set-variable f y`, 1, true},
		{`$f = x; ${f}.m()`, 1, true},
		{`$f = x; w $f; w "a $f"; w ('a' + $f)`, 1, false},
		{`$f = x; '{0}' -f 1; get-item d/f/f.txt`, 1, false},
		{`$fa = x; $af.m(); $f_x`, 0, false},
	} {
		assignments, rebinds := psVariableUses(row.text, "f")
		if assignments != row.assignments || rebinds != row.rebinds {
			t.Errorf("psVariableUses(%s) = %d %v, want %d %v", row.text, assignments, rebinds, row.assignments, row.rebinds)
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

// GAP-1276: the commands that may bind a variable by a name the reader
// cannot read as text, and ordinary ones that name theirs literally.
func TestGAP1276DynamicVariableWriteUnits(t *testing.T) {
	for _, row := range []struct {
		text string
		want bool
	}{
		{`set-variable -name ([char]95) -value (get-item 'x'); $_.delete()`, true},
		{`sv ([char]102) 1`, true},
		{`set -name ("f") -value 1`, true},
		{`new-variable -name $n -value 1`, true},
		{`set-variable -name f -include x -value 1`, true},
		{`$executioncontext.sessionstate.psvariable.set([char]95, 1)`, true},
		{`(get-variable -name '[e-g]').value = 1`, true},
		{`(gv)[0].value = 1`, true},
		{`gv | out-null`, true},
		{`iex ([char]36 + 'f = 1')`, true},
		{`'$f = 1' | invoke-expression`, true},
		{`set-item -path ('variab' + 'le:f') -value 1`, true},
		{`ni -path $p -value 1`, true},
		{`get-item variable:f`, true},
		{`& $c -name f -value 1`, true},
		{`& ('set-' + 'variable') f 1`, true},
		{`& 'set-variable' -name ([char]102) -value 1`, true},
		{`. $s`, true},
		{`get-item x -outvariable ([char]102)`, true},
		{`get-item x -ov:$n`, true},
		{`[scriptblock]::create($t).invoke()`, true},
		{`sal q sv; q ([char]102) 1`, true},
		{`get-item x | tee-object -variable ([char]102)`, true},
		{`set-content -path (variab + le:f) -value 1`, true},
		{`[powershell]::create(currentrunspace).addscript($t).invoke()`, true},
		{`set-variable -name count -value (get-date)`, false},
		{`set-variable count 0 -scope global -force`, false},
		{`sv -name:f -value 1`, false},
		{`get-variable -name f -valueonly`, false},
		{`get-item x -outvariable items`, false},
		{`write-host 'set up'; $f = get-item 'a'; $f.delete() 2>&1`, false},
		{`get-childitem 'bin' | foreach-object { $_.delete() }`, false},
		{`copy-item 'a' 'b'; & { $x = 1 }; . { 1 }; ./build.ps1`, false},
		{`cmd /c x && y`, false},
		{`set-content out.txt x; get-item a | tee-object -variable items`, false},
		{`$h = @{}; $h.values | out-null; $o.valuex = 1`, false},
	} {
		if got := psDynamicVariableWrite(row.text, &psBudget{}); got != row.want {
			t.Errorf("psDynamicVariableWrite(%s) = %v, want %v", row.text, got, row.want)
		}
	}
}
