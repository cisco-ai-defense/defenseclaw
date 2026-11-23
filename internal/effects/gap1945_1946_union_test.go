// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import "testing"

// TestGAP1945ReaderNotesOnRunningPowerShellKeepTheirUnknowns pins the GAP-1945
// refutation (TST-13269: 280 gateway cells with the same verdict at T20, T21a
// and T21f): a guessed PowerShell call with POSIX-only text whose PowerShell
// reading only carries a reader note (a fused backtick-e escape, which pwsh
// parses and runs) keeps that unknown. Only a parse error pwsh reports itself
// (psparse Diagnostic.Syntax) makes the POSIX reading the whole call.
func TestGAP1945ReaderNotesOnRunningPowerShellKeepTheirUnknowns(t *testing.T) {
	const bashrc = `C:\Users\alice\.bashrc`
	for _, cmd := range []string{
		"Set-Content -Path " + bashrc + " -Value a\"`e\"b # <<`",
		"Get-Date -Format a\"`e\"b; Get-Item " + bashrc + " # <<`",
	} {
		r := Extract(Call{Surface: SurfaceShell, Tool: "shell", Command: cmd}, gap1915Options())
		if len(r.Unknowns) == 0 {
			t.Errorf("%q: the reader note of PowerShell that runs was cleared by the POSIX reading", cmd)
		}
	}
}

// TestGAP1945ParseErrorTakesEveryPOSIXEffect: red at ad6ab569dd (a PowerShell
// parse error cleared the unknowns but only the POSIX mutations were added, so
// the POSIX read of the redirection source was lost), green when the POSIX
// reading of a script pwsh refuses to parse is added whole.
func TestGAP1945ParseErrorTakesEveryPOSIXEffect(t *testing.T) {
	const bashrc = `C:\Users\alice\.bashrc`
	cmd := `Get-Content x.txt < '` + bashrc + `' # <<`
	r := Extract(Call{Surface: SurfaceShell, Tool: "shell", Command: cmd}, gap1915Options())
	if len(r.Unknowns) != 0 {
		t.Errorf("unknowns %v: pwsh runs nothing of a script it cannot parse, the POSIX reading is the call", r.Unknowns)
	}
	found := false
	for _, e := range r.Effects {
		if e.Kind == KindRead && e.Target.Path == bashrc && e.TargetState == TargetStateKnown && e.RoleState == RoleStateKnown {
			found = true
			if !e.Cond {
				t.Errorf("the POSIX read is not Cond: %+v", e)
			}
		}
	}
	if !found {
		t.Errorf("no known read of %s in %+v", bashrc, r.Effects)
	}
}

// TestGAP1946GuessedEffectIsMergedNotReplaced: red at ad6ab569dd (the known
// POSIX write replaced the guessed reading's unresolved write of the same
// target and its data, with the content it carried, was lost), green when the
// guessed effect is merged in place: the POSIX target and role, Cond, and the
// stronger data of the two.
func TestGAP1946GuessedEffectIsMergedNotReplaced(t *testing.T) {
	const p = `C:\Users\alice\proj\o.txt`
	guessed := Effect{Kind: KindWrite, Target: Target{Type: TargetPath, Path: p}, TargetState: TargetStateKnown, RoleState: RoleStateUnknown,
		Data: &Data{Kind: DataLiteral, Bytes: 64, Text: "the longer content the guessed reading carried to the same file....."}}
	res := Result{Surface: SurfaceShell, Flavor: FlavorWindows, Dialect: DialectPowerShell, Effects: []Effect{guessed}}
	gap1946Union(&res, Call{Surface: SurfaceShell, Tool: "shell", Command: `printf x > '` + p + `'`}, gap1915Options())
	var got []Effect
	for _, e := range res.Effects {
		if e.Kind == KindWrite && e.Target.Path == p {
			got = append(got, e)
		}
	}
	if len(got) == 0 {
		t.Fatalf("no write of %s in %+v", p, res.Effects)
	}
	for _, e := range got {
		if e.TargetState != TargetStateKnown || e.RoleState != RoleStateKnown || !e.Cond {
			t.Errorf("merged write not known and Cond: %+v", e)
		}
		if e.Data == nil || e.Data.Bytes != 64 || e.Data.Text != guessed.Data.Text {
			t.Errorf("merged write lost the guessed data: %+v", e.Data)
		}
	}
}

// gap1946Union is the union of a guessed PowerShell reading (no parse error)
// with the POSIX reading of call.
func gap1946Union(res *Result, call Call, o Options) {
	unionPOSIXReading(res, DialectPowerShell, false, call, o)
}
