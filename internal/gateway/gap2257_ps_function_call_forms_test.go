// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import "testing"

// rel-1-0-10:GAP-2257: a call of a PowerShell function the script defines
// runs its body whatever the call form, so the folder its cd (or
// Push-Location) moves to holds for the write after the call: with an
// argument or a switch, piped, redirected, dot-sourced, through an alias the
// script sets, a filter, or a global: definition gets the cell of the plain
// spelling, on every route; a body write runs at the call. The attack rows
// read the profile (needsHome: on a Linux test gateway only the managed hook
// peer carries it). A project folder in the body keeps allow, and a function
// named like a built-in alias does not replace the alias.
func TestGAP2257PowerShellFunctionCallFormsFiveTiersWindowsHost(t *testing.T) {
	useDefaultEffectsLane(t)
	gap0589WindowsHost(t)
	const project = `C:\Users\alice\project`
	const write = `; Set-Content -Path config.yaml -Value x`
	const body = `function g { cd ..\.defenseclaw }; `
	ctl := `ctl:Set-Content -Path C:\Users\alice\.defenseclaw\config.yaml -Value x`
	rows := []r3TierRow{}
	for _, f := range []struct{ name, call string }{
		{"call with an argument", body + `g 1`},
		{"call with a switch", body + `g -x`},
		{"piped call", body + `g | Out-Null`},
		{"redirected call", body + `g > $null`},
		{"dot-sourced call", body + `. g`},
		{"alias call", body + `Set-Alias zg g; zg`},
		{"global: definition", `function global:g { cd ..\.defenseclaw }; g`},
		{"filter", `filter g { cd ..\.defenseclaw }; g`},
		{"Push-Location body, call with an argument", `function g { Push-Location ..\.defenseclaw }; g 1`},
	} {
		rows = append(rows, r3TierRow{gap: "GAP-2257 " + f.name, command: f.call + write, cwd: project, want: ctl, needsHome: true})
	}
	rows = append(rows,
		r3TierRow{gap: "GAP-2257 body write, call with an argument", command: `function g { Set-Content -Path C:\Users\alice\.defenseclaw\config.yaml -Value x }; g 1`,
			cwd: project, want: ctl, needsHome: true},
		r3TierRow{gap: "GAP-2257 fp: project folder in the body, call with an argument", command: `function g { cd src }; g 1; Set-Content -Path config.yaml -Value x`,
			cwd: project, want: "allow"},
		r3TierRow{gap: "GAP-2257 fp: function named like a built-in alias", command: `function cd { }; cd src; Set-Content -Path notes.txt -Value x`,
			cwd: project, want: "allow"},
	)
	r3CheckWindowsTierRows(t, r3WindowsRoutes(), rows)
}
