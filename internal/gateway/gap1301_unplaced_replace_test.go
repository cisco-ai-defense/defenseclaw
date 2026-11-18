// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// GAP-1301 (s7-rv1257r2 R01-R08): a FileInfo Replace on a variable or a
// pipeline item the reader placed but is not sure of (the command may bind
// a variable by a name built at run time: & $c, iex, the SessionState and
// PSVariable APIs, the variable: drive; or a second assignment it cannot
// place) is read as Delete and CopyTo are: the unknown tier or the write
// rule of the file, never allowed with no rule. R05 is the control with no
// run-time name.
func TestGAP1301UnsureReceiverReplace(t *testing.T) {
	gap1275Check(t, []gap1257Row{
		gap1275Unknown("R01 replace arg + sessionstate text", "$f = Get-Item 'notes.txt'; $f.Replace(%s, 'notes.bak'); Write-Host 'sessionstate'"),
		gap1275Unknown("R02 replace receiver + variable: text", "$f = Get-Item %s; $f.Replace('notes.txt', 'notes.bak'); Write-Host 'variable:x'"),
		gap1275Unknown("R03 replace item + scriptblock text", "Get-Item %s | ForEach-Object { $_.Replace('notes.txt', 'notes.bak') }; Write-Host 'scriptblock'"),
		gap1275Unknown("R04 replace receiver + run-time call", "$c = 'Write-Host'; & $c hi; $f = Get-Item %s; $f.Replace('notes.txt', 'notes.bak')"),
		gap1275Unknown("R05 replace receiver control", "$f = Get-Item %s; $f.Replace('notes.txt', 'notes.bak')"),
		gap1275Unknown("R06 copyto arg + sessionstate text", "$f = Get-Item 'notes.txt'; $f.CopyTo(%s, $true); Write-Host 'sessionstate'"),
		gap1275Unknown("R07 delete receiver + psvariable text", "$f = Get-Item %s; $f.Delete(); Write-Host 'psvariable'"),
		gap1275Unknown("R08 replace receiver + iex literal", "$f = Get-Item %s; $f.Replace('notes.txt', 'notes.bak'); iex 'Write-Host hi'"),
		gap1275Unknown("R09 replace receiver + unplaced re-assignment", "$f = Get-Item %s; $f = $f; $f.Replace('notes.txt', 'notes.bak')"),
		gap1275Unknown("R10 replace psitem + iex literal", "Get-Item %s | ForEach-Object { $PSItem.Replace('notes.txt', 'notes.bak') }; iex 'Write-Host hi'"),
	})
}

// GAP-1301 units: a Replace on a receiver the reader placed but is not sure
// of writes its arguments and its receiver in the unknown tier; one on a
// receiver the reader knows nothing of (String.Replace) stays nothing, also
// in a command with a run-time name.
func TestGAP1301UnsureReadings(t *testing.T) {
	for _, row := range []struct {
		text   string
		opens  int
		unsure bool
	}{
		{"$s = 'x.txt'; $s.Replace('x', 'y'); iex 'Write-Host hi'", 0, false},
		{"$s = 'x.txt'; $s.Replace('x', 'y')", 0, false},
		{"$f = Get-Item 'a'; $f.Replace('b', 'c'); iex 'Write-Host hi'", 3, true},
		{"$f = Get-Item 'a'; $f = $f; $f.Replace('b', 'c')", 3, true},
		{"$f = Get-Item 'a'; $f.Replace('b', 'c')", 3, false},
	} {
		scan := newPSScan([]rune(row.text), nil)
		scan.code(0, false)
		if len(scan.opens) != row.opens {
			t.Errorf("%s: opens %+v, want %d", row.text, scan.opens, row.opens)
			continue
		}
		unknown := 0
		for _, open := range scan.opens {
			if open.unknown {
				unknown++
			}
		}
		if row.unsure && (!scan.unplaced || unknown != row.opens) || !row.unsure && (scan.unplaced || unknown != 0) {
			t.Errorf("%s: unplaced=%v opens %+v, want the unknown tier %v", row.text, scan.unplaced, scan.opens, row.unsure)
		}
	}
}
