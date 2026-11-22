// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import "testing"

// TestPSFusedNativeArg: PowerShell hands a native program a switch and the
// argument glued to it as one argv word (DET111 R1, GAP-1663: the S4-R2 7z -o
// row reads the folder from that word); a cmdlet binds the value to the
// parameter, and a blank keeps two words.
func TestPSFusedNativeArg(t *testing.T) {
	words := func(src string) []Word {
		s := parsePowerShell(src, Options{Flavor: FlavorWindows, Dialect: DialectPowerShell})
		if len(s.Stmts) != 1 || len(s.Stmts[0].Cmds) != 1 {
			t.Fatalf("%q: want one command, got %+v", src, s.Stmts)
		}
		return s.Stmts[0].Cmds[0].Words
	}
	ws := words(`tool x a.bin -o$env:TEMP\out`)
	if len(ws) != 4 {
		t.Fatalf("fused switch: want 4 words, got %d: %+v", len(ws), ws)
	}
	got := ws[3].Segs
	if len(got) != 3 || got[0].Lit != "-o" || got[1].Var != "TEMP" || got[2].Lit != `\out` {
		t.Fatalf("fused switch word: got %+v", got)
	}
	w := newWalker(&Result{}, Options{Flavor: FlavorWindows, Env: map[string]string{"TEMP": `C:\t`}})
	if rv := w.resolveWord(ws[3]); !rv.Static || rv.Value != `-oC:\t\out` {
		t.Fatalf("fused switch resolves to %+v", rv)
	}
	if ws := words(`tool x a.bin -o:x`); len(ws) != 5 {
		t.Fatalf("-o:value keeps the switch and its value: got %d words", len(ws))
	}
	if ws := words(`tool x a.bin -o $env:TEMP`); len(ws) != 5 || ws[3].Value != "-o" {
		t.Fatalf("a blank keeps two words: got %+v", ws)
	}
	if ws := words(`Write-Output -o$env:TEMP`); len(ws) != 3 || ws[1].Value != "-o" {
		t.Fatalf("a cmdlet binds the value to the parameter: got %+v", ws)
	}
}
