// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

// GAP-1779 (review round 1 R1-2): the single-quote state that keeps a
// literal $HOME from reading as the home was flipped by every ASCII
// apostrophe before the scan, so an apostrophe in a comment, a smart
// quote or a backtick-escaped quote hid $HOME / $env:USERPROFILE in a
// later protected write. The scanner now applies it by the quotes it
// reads, the unread fallback reads the command as written, and the key-read
// proof reads an unreadable command piece by piece.
func TestActionWindowsLiteralDollarFollowsTheScannedQuotes(t *testing.T) {
	const home, cwd = `C:\Users\u`, `C:\Users\u\proj`
	for _, tc := range []struct {
		name, command, want string
	}{
		{"W06 comment apostrophe then $HOME write", "# set up the user's key\nSet-Content $HOME\\.ssh\\authorized_keys k", "protected-target"},
		{"W07 comment apostrophe then USERPROFILE", "# set up the user's key\nAdd-Content -Path $env:USERPROFILE\\.ssh\\authorized_keys k", "protected-target"},
		{"W03 smart quote then $HOME write", "Write-Output ’a'; Set-Content $HOME\\.ssh\\authorized_keys k", "protected-target"},
		{"W08 escaped quotes around a $HOME write", "Write-Output `'; Set-Content $HOME\\.ssh\\authorized_keys k; Write-Output `'", "protected-target"},
		{"literal $HOME in single quotes is text", "Write-Output '$HOME\\.ssh\\authorized_keys is the file'", ""},
		{"literal $HOME in a literal here-string is text", "Write-Output @'\n$HOME\\.ssh\\authorized_keys\n'@", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ActionCommandDecision(tc.command, cwd, home); got != tc.want {
				t.Fatalf("ActionCommandDecision(%q) = %q, want %q", tc.command, got, tc.want)
			}
		})
	}
	if !ActionPrivateKeyRead("Get-Content ~\\.ssh\\id_ed25519; Write-Output 'unterminated", cwd, home) {
		t.Error("an unreadable command that reads the key is a key read")
	}
}
