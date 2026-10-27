// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

// GAP-1523: Invoke-Expression parses its text again, so a $HOME that an
// @'...'@ here-string or a single-quoted string kept literal is expanded
// when the text runs. The scan now reads the text iex runs.
func TestActionWindowsInvokeExpressionTextIsScanned(t *testing.T) {
	const home, cwd = `C:\Users\u`, `C:\Users\u\proj`
	for _, tc := range []struct {
		name, command, want string
	}{
		{"BYP-R104-N-WIN-BODY-IEX piped here-string", "@'\nAdd-Content $HOME\\.ssh\\authorized_keys k\n'@ | Invoke-Expression", "protected-target"},
		{"iex single-quoted argument", "iex 'Set-Content $HOME\\.ssh\\authorized_keys k'", "protected-target"},
		{"Invoke-Expression -Command", "Invoke-Expression -Command 'Add-Content $env:USERPROFILE\\.ssh\\authorized_keys k'", "protected-target"},
		{"iex of a project write", "@'\nSet-Content notes.txt k\n'@ | Invoke-Expression", ""},
		{"printed literal $HOME is text", "Write-Output '$HOME\\.ssh\\authorized_keys is the file'", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ActionCommandDecision(tc.command, cwd, home); got != tc.want {
				t.Fatalf("ActionCommandDecision(%q) = %q, want %q", tc.command, got, tc.want)
			}
		})
	}
}
