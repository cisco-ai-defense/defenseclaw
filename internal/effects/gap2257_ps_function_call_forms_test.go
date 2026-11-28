// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"slices"
	"testing"
)

// rel-1-0-10:GAP-2257: a call of a function the script defines runs its body
// whatever its call form: with arguments or a switch, piped, fed by a pipe,
// redirected, dot-sourced, through an alias the script sets, a filter, or a
// scope-qualified definition. A Set-Location or Push-Location in the body
// then moves the folder of the statements after the call, as for the bare
// call (GAP-1156). A name PowerShell resolves to a built-in alias first, and
// a body that moves to a parameter, keep the folder unknown.
func TestGAP2257PowerShellFunctionCallFormsMoveFolder(t *testing.T) {
	const home = `C:\Users\alice`
	const state = home + `\.defenseclaw\config.yaml`
	const write = `; Set-Content -Path config.yaml -Value x`
	opts := Options{Flavor: FlavorWindows, Dialect: DialectPowerShell, Home: home, CWD: home}
	cases := []struct {
		command string
		want    string // a known unconditional write target, "" = the folder is unknown
	}{
		{`function g { cd .defenseclaw }; g 1` + write, state},
		{`function g { cd .defenseclaw }; g -x` + write, state},
		{`function g { cd .defenseclaw }; g -Path:a` + write, state},
		{`function g { cd .defenseclaw }; g | Out-Null` + write, state},
		{`function g { cd .defenseclaw }; "x" | g` + write, state},
		{`function g { cd .defenseclaw }; g > $null` + write, state},
		{`function g { cd .defenseclaw }; . g` + write, state},
		{`function g { cd .defenseclaw }; . g 1` + write, state},
		{`function g { cd .defenseclaw }; Set-Alias zg g; zg` + write, state},
		{`function g { cd .defenseclaw }; New-Alias -Name zg -Value g; zg 1` + write, state},
		{`function g { cd .defenseclaw }; sal -n zg -v:g; zg` + write, state},
		{`function g { cd .defenseclaw }; Set-Alias h g -Force; h` + write, state},
		{`function global:g { cd .defenseclaw }; g` + write, state},
		{`function Script:g { cd .defenseclaw }; g 1` + write, state},
		{`filter g { cd .defenseclaw }; g` + write, state},
		{`function g { Push-Location .defenseclaw }; g 1` + write, state},
		{`function g { "x" }; g > out.txt`, home + `\out.txt`},
		{`function g { Set-Content -Path C:\Users\alice\.defenseclaw\config.yaml -Value x }; g 1`, state},
		// the folder stays unknown
		{`function g { param($d) Set-Location $d }; g .defenseclaw` + write, ""},
		{`function cd { }; cd .defenseclaw` + write, ""},
		{`function g { cd .defenseclaw }; Set-Alias h g; h` + write, ""},
		{`function g { cd .defenseclaw }; Set-Alias zg g -WhatIf; zg` + write, home + `\config.yaml`},
		{`function g { g 1 }; g 1` + write, ""},
	}
	for _, tc := range cases {
		res := Extract(Call{Surface: SurfaceShell, Command: tc.command}, opts)
		var known []string
		unknown := false
		for _, e := range res.Effects {
			if e.Kind != KindWrite {
				continue
			}
			if e.TargetState == TargetStateKnown && !e.Cond {
				known = append(known, e.Target.Path)
			} else if e.TargetState != TargetStateKnown {
				unknown = true
			}
		}
		if tc.want == "" {
			if !unknown {
				t.Errorf("%q: the write is placed (%q), want an unknown folder", tc.command, known)
			}
			continue
		}
		if !slices.Contains(known, tc.want) {
			t.Errorf("%q: known writes %q, want %q (effects %+v)", tc.command, known, tc.want, res.Effects)
		}
	}
}
