// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

// The Windows scanner follows PowerShell's comments and smart quotes, so an
// apostrophe in a comment no longer makes an ordinary read of ~/.ssh
// unreadable. A command the scanner still cannot read blocks only on a
// protected-named word outside a plain read, and never on the bare .ssh
// directory (GAP-1500 refix, review round 1 R1-3; the five WB rows were
// allowed before 93ccfc2817 and blocked after it).
func TestActionWindowsCommentsAndSmartQuotesKeepReadsAllowed(t *testing.T) {
	const home, cwd = `C:\Users\dcw4-std2`, `C:\Users\dcw4-std2\proj`
	for _, tc := range []struct {
		name, command, want string
	}{
		{"WB1 comment line then Test-Path", "# Check the user's SSH folder\nTest-Path ~\\.ssh", ""},
		{"WB2 read with a comment", "Get-Content ~\\.ssh\\authorized_keys # who's allowed", ""},
		{"WB3 Git Bash listing with a comment", "ls -la ~/.ssh  # what's there", ""},
		{"WB4 POSIX quote idiom then a listing", "printf '%s\\n' 'it'\\''s' > notes.txt; ls -la ~/.ssh", ""},
		{"WB7 Get-ChildItem with a comment", "Get-ChildItem ~\\.ssh # don't print keys", ""},
		{"block comment then a read", "<# it's a check #> Get-Content ~\\.ssh\\config", ""},
		{"smart quoted filter on a listing", "Get-ChildItem ~\\.ssh -Filter ’*.pub’ # it's", ""},
		{"smart double quotes around a path", "Test-Path “~\\.ssh\\authorized_keys” # it's", ""},
		{"unreadable read of authorized_keys", "Get-Content ~\\.ssh\\authorized_keys; Write-Output 'unterminated", ""},
		{"unreadable listing of the bare directory", "Write-Output 'x\nls ~\\.ssh", ""},
		{"hash inside a word is not a comment", "Write-Output a#b", ""},
		// Protected writes still block, whatever the comments and quotes.
		{"write before a comment", "Set-Content ~\\.ssh\\authorized_keys k # it's mine", "protected-target"},
		{"write after a comment line", "# set up the user's key\nSet-Content ~\\.ssh\\authorized_keys k", "protected-target"},
		{"write after a block comment", "<# it's\nmine #>\nAdd-Content -Path ~\\.ssh\\authorized_keys -Value k", "protected-target"},
		{"write after smart quoted text", "Write-Output ’a’; Set-Content ~\\.ssh\\authorized_keys k", "protected-target"},
		{"smart quoted protected target", "Set-Content ‘~\\.ssh\\authorized_keys’ k", "protected-target"},
		{"delete of the directory with a comment", "Remove-Item -Recurse ~\\.ssh # it's old", "protected-target"},
		{"unreadable redirect to a key file", "printf 'it'\\''s' > ~/.ssh/authorized_keys", "protected-target"},
		{"unreadable write after cd into .ssh", "cd ~\\.ssh; Set-Content authorized_keys k; Write-Output 'x", "protected-target"},
		{"unreadable read redirected to a key file", "Get-Content k.pub > ~\\.ssh\\authorized_keys; Write-Output 'x", "protected-target"},
		{"unterminated block comment hiding a write", "<# Set-Content ~\\.ssh\\authorized_keys k", "protected-target"},
		{"smart here-string patch to a protected target", "apply_patch @’\n*** Begin Patch\n*** Add File: ~\\.ssh\\authorized_keys\n+it's\n*** End Patch\n’@", "protected-target"},
		{"smart here-string patch to a project file", "apply_patch @’\n*** Begin Patch\n*** Add File: notes.txt\n+it's\n*** End Patch\n’@", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ActionCommandDecision(tc.command, cwd, home); got != tc.want {
				t.Fatalf("ActionCommandDecision(%q) = %q, want %q", tc.command, got, tc.want)
			}
		})
	}
	// The private-key proof reads the same grammar.
	for _, command := range []string{
		"Get-Content ~\\.ssh\\id_ed25519 # it's mine",
		"Get-Content ~\\.ssh\\id_ed25519; Write-Output ’done’",
	} {
		if !ActionPrivateKeyRead(command, cwd, home) {
			t.Errorf("ActionPrivateKeyRead(%q) = false, want a key read", command)
		}
	}
	if ActionPrivateKeyRead("Get-Content ~\\.ssh\\config # it's mine", cwd, home) {
		t.Error("a config read with a comment is not a key read")
	}
}
