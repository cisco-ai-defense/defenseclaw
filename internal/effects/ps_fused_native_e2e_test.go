// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"strings"
	"testing"
)

// TestPSFusedNativeArgEndToEnd: from the PowerShell text through Extract, the
// 7z -o folder is the argv word PowerShell hands 7z (DET111 R1, GAP-1663;
// S4-R2 7z row). Oracle (pwsh 7.6.6 and Windows PowerShell 5.1): the quoted
// "-o$env:USERPROFILE\proj\out" expands, so it is the subtree write at the
// placed folder; the unquoted -o$env:USERPROFILE\proj\out is the parameter
// o$env with the argument USERPROFILE\proj\out and reaches 7z as that literal
// text, so the write is never the USERPROFILE folder: it is a folder named
// $env:... under the cwd (not a canonical Windows path: an unknown target).
func TestPSFusedNativeArgEndToEnd(t *testing.T) {
	base := Options{Flavor: FlavorWindows, Dialect: DialectPowerShell, CWD: `C:\Users\alice\w`, Drive: "C", CaseInsensitive: true, Home: `C:\Users\alice`}
	known := base
	known.Env = map[string]string{"USERPROFILE": `C:\Users\alice`}
	placed := func(r Result) bool {
		for _, e := range r.Effects {
			if e.Kind == KindWrite && e.Target.Subtree && e.Target.Key() == `c:\users\alice\proj\out` {
				return true
			}
		}
		return false
	}
	r := Extract(Call{Surface: SurfaceShell, Command: `7z x a.7z "-o$env:USERPROFILE\proj\out"`}, known)
	if !placed(r) {
		t.Errorf("quoted, known USERPROFILE: no subtree write at the -o folder:\n%s", fmtRes(r))
	}
	for _, o := range []Options{known, base} {
		r = Extract(Call{Surface: SurfaceShell, Command: `7z x a.7z -o$env:USERPROFILE\proj\out`}, o)
		if placed(r) {
			t.Errorf("unquoted: the literal -o$env: word must not be read as the USERPROFILE folder:\n%s", fmtRes(r))
		}
		w := false
		for _, e := range r.Effects {
			if e.Kind == KindWrite && e.Target.Path == "" && strings.EqualFold(e.Origin.Program, "7z") {
				w = true
			}
		}
		if !w {
			t.Errorf("unquoted: want the 7z write with an unknown target:\n%s", fmtRes(r))
		}
	}
}
