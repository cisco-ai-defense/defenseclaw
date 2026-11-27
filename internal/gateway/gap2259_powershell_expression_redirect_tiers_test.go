// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import "testing"

// rel-1-0-10:GAP-2259: the expression-statement redirect spellings get the
// unknown tier of the command-redirect and cmdlet spellings after
// Set-Location $env:X (lead ruling 2026-11-26 option 2) in every tier, on the
// project and the home folder; config.yaml stays the documented limit.
func TestGAP2259PowerShellExpressionRedirectFiveTiersWindowsHost(t *testing.T) {
	useDefaultEffectsLane(t)
	gap0589WindowsHost(t)
	rows := []r3TierRow{}
	for _, cwd := range []string{`C:\Users\alice\project`, `C:\Users\alice`} {
		for _, f := range []struct{ name, command string }{
			{"append", `Set-Location $env:X; "k" >> authorized_keys`},
			{"write", `Set-Location $env:X; "k" > authorized_keys`},
			{"in .ssh", `Set-Location $env:X; "k" >> .ssh\authorized_keys`},
			{"parenthesized", `Set-Location $env:X; ("k") >> authorized_keys`},
		} {
			rows = append(rows, r3TierRow{gap: "GAP-2259 " + f.name + " at " + cwd, command: f.command, cwd: cwd, want: "maybe"})
		}
		rows = append(rows,
			r3TierRow{gap: "GAP-2259 limit: config.yaml at " + cwd, command: `Set-Location $env:X; "k" > config.yaml`, cwd: cwd, want: "allow"},
			r3TierRow{gap: "GAP-2259 fp: project file at " + cwd, command: `Set-Location $env:X; "k" > notes.txt`, cwd: cwd, want: "allow"},
		)
	}
	r3CheckWindowsTierRows(t, r3WindowsRoutes(), rows)
}
