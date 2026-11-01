// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

// GAP-1799: a read or listing of ~/.ssh was denied when another statement of
// the same command was not a read, because the read-only skip needed every
// statement to be a read. Each list element is now judged on its own
// targets; a location change into ~/.ssh still places the writes after it.
// GAP-1473: PowerShell passes a quoted ~ path to Write-Output or git as
// text; only a cmdlet path parameter or a redirect reads it as the home.
func TestActionWindowsStatementsAreJudgedOnTheirOwnTargets(t *testing.T) {
	const home, cwd = `C:\Users\u`, `C:\Users\u\proj`
	for _, tc := range []struct {
		name, command, want string
	}{
		{"WB8 printed text then a listing", "Write-Output \"it's done\"; Get-ChildItem ~\\.ssh", ""},
		{"printed text then a listing", "Write-Output 'it is'; Get-ChildItem ~\\.ssh", ""},
		{"project write then a read of authorized_keys", "Set-Content notes.txt k; Get-Content ~\\.ssh\\authorized_keys", ""},
		{"listing then a protected write", "Get-ChildItem ~\\.ssh; Set-Content ~\\.ssh\\authorized_keys k", "protected-target"},
		{"listing piped into a delete", "Get-ChildItem ~\\.ssh | Remove-Item", "protected-target"},
		{"location chain into .ssh then a write", "Push-Location ~\\.ssh; Pop-Location; Add-Content notes.txt ok", "protected-target"},
		{"read redirected to a protected file", "Get-Content k.pub > ~\\.ssh\\authorized_keys; Write-Output ok", "protected-target"},
		{"GAP-1473 printed quoted tilde path", "Write-Output '~/.ssh/authorized_keys'", ""},
		{"GAP-1473 git message", "git commit -m 'Document ~/.ssh/authorized_keys'", ""},
		{"GAP-1473 cmdlet path parameter", "Set-Content '~/.ssh/authorized_keys' k", "protected-target"},
		{"GAP-1473 printed text redirected to the key", "Write-Output 'k' > '~/.ssh/authorized_keys'", "protected-target"},
		{"GAP-1473 subexpression still runs", "Write-Output \"$(Set-Content ~\\.ssh\\authorized_keys k)\"", "protected-target"},
		{"GAP-1473 printed absolute path", "Write-Output 'C:\\Users\\u\\.ssh\\authorized_keys'", "protected-target"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ActionCommandDecision(tc.command, cwd, home); got != tc.want {
				t.Fatalf("ActionCommandDecision(%q) = %q, want %q", tc.command, got, tc.want)
			}
		})
	}
}
