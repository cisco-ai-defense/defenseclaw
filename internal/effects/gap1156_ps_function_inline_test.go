// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import "testing"

// rel-1-0-10:GAP-1156: a plain call of a function the script defines runs
// its body in the session, so a Set-Location in the body moves the folder
// of the statements after the call; the definition alone moves nothing. A
// call with arguments, a recursive call and a dynamic call keep the walker's
// unknown folder.
func TestGAP1156PowerShellFunctionCallMovesFolder(t *testing.T) {
	const home = `C:\Users\alice`
	opts := Options{Flavor: FlavorWindows, Dialect: DialectPowerShell, Home: home, CWD: home}
	cases := []struct {
		command string
		want    string // the known write target, "" = the folder is unknown
	}{
		{`function g { cd .defenseclaw }; g; Set-Content -Path config.yaml -Value x`, home + `\.defenseclaw\config.yaml`},
		{`function g { cd .defenseclaw }; & g; Set-Content -Path config.yaml -Value x`, home + `\.defenseclaw\config.yaml`},
		{`function G { Set-Location .defenseclaw }; g; Set-Content -Path config.yaml -Value x`, home + `\.defenseclaw\config.yaml`},
		{`function g { cd .defenseclaw }; Set-Content -Path config.yaml -Value x`, home + `\config.yaml`},
		{"function g { cd .defenseclaw }\ng\nSet-Content -Path config.yaml -Value x", home + `\.defenseclaw\config.yaml`},
		{`function g { cd .defenseclaw }; g x; Set-Content -Path config.yaml -Value x`, ""},
		{`function g { g }; g; Set-Content -Path config.yaml -Value x`, ""},
		{`function g { cd .defenseclaw }; & $n; Set-Content -Path config.yaml -Value x`, ""},
	}
	for _, tc := range cases {
		res := Extract(Call{Surface: SurfaceShell, Command: tc.command}, opts)
		got := ""
		unknown := false
		for _, e := range res.Effects {
			if e.Kind != KindWrite {
				continue
			}
			if e.TargetState == TargetStateKnown && !e.Cond {
				got = e.Target.Path
			} else if e.TargetState != TargetStateKnown {
				unknown = true
			}
		}
		if tc.want == "" {
			if !unknown {
				t.Errorf("%q: the write is placed (%q), want an unknown folder", tc.command, got)
			}
			continue
		}
		if got != tc.want {
			t.Errorf("%q: known write %q, want %q (effects %+v)", tc.command, got, tc.want, res.Effects)
		}
	}
}
