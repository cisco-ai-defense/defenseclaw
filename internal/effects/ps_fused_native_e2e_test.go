// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import "testing"

// TestPSFusedNativeArgEndToEnd: from the PowerShell text through Extract, a 7z
// -o folder glued to $env:USERPROFILE is the extraction's subtree write -- a
// placed folder when the hook knows USERPROFILE, an unknown folder that keeps
// its literal tail when it does not (DET111 R1, GAP-1663; S4-R2 7z row).
func TestPSFusedNativeArgEndToEnd(t *testing.T) {
	src := `7z x a.7z -o$env:USERPROFILE\proj\out`
	base := Options{Flavor: FlavorWindows, Dialect: DialectPowerShell, CWD: `C:\Users\alice\w`, Drive: "C", CaseInsensitive: true, Home: `C:\Users\alice`}
	known := base
	known.Env = map[string]string{"USERPROFILE": `C:\Users\alice`}
	r := Extract(Call{Surface: SurfaceShell, Command: src}, known)
	found := false
	for _, e := range r.Effects {
		if e.Kind == KindWrite && e.Target.Subtree && e.Target.Key() == `c:\users\alice\proj\out` {
			found = true
		}
	}
	if !found {
		t.Errorf("known USERPROFILE: no subtree write at the -o folder:\n%s", fmtRes(r))
	}
	r = Extract(Call{Surface: SurfaceShell, Command: src}, base)
	found = false
	for _, e := range r.Effects {
		if e.Kind == KindWrite && e.Target.Path == "" && e.Target.Spelling == `$?\proj\out` {
			found = true
		}
	}
	if !found {
		t.Errorf("unknown USERPROFILE: no unknown write keeping the -o tail:\n%s", fmtRes(r))
	}
}
