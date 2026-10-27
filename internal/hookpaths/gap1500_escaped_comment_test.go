// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

// GAP-1500 refix 2 (review round 2 R2-1, regression of e949d2de0a): a # after
// a backtick-escaped blank is part of a word in PowerShell, and Git Bash
// (Claude Code's Bash tool on a Windows home) reads neither PowerShell
// comments nor smart quotes. A protected write or key read after such a
// misread comment was hidden from every check. The scanner now follows the
// PowerShell escape rule, and a protected decision holds when either the
// PowerShell reading or the plain reading finds the target. Reads and
// listings of ~/.ssh with comments stay allowed.
func TestActionWindowsEscapedCommentKeepsTheProtectedTarget(t *testing.T) {
	const home, cwd = `C:\Users\u`, `C:\Users\u\proj`
	for _, tc := range []struct {
		name, command, want string
	}{
		{"W01 escaped blank then #", "Write-Output a` #; Set-Content ~\\.ssh\\authorized_keys k", "protected-target"},
		{"W02 Add-Content USERPROFILE", "Write-Output a` #; Add-Content -Path $env:USERPROFILE\\.ssh\\authorized_keys k", "protected-target"},
		{"W03 redirect", "Write-Output a` #; echo k >> ~\\.ssh\\authorized_keys", "protected-target"},
		{"G02 Git Bash lone CR before #", "echo a\r#x; cp k.pub ~/.ssh/authorized_keys", "protected-target"},
		{"escaped quote then write", "Write-Output `'; Set-Content ~\\.ssh\\authorized_keys k", "protected-target"},
		{"line continuation then write", "Set-Content `\n ~\\.ssh\\authorized_keys k", "protected-target"},
		{"WB1 still allowed", "# Check the user's SSH folder\nTest-Path ~\\.ssh", ""},
		{"WB2 still allowed", "Get-Content ~\\.ssh\\authorized_keys # who's allowed", ""},
		{"WB3 still allowed", "ls -la ~/.ssh  # what's there", ""},
		{"WB7 still allowed", "Get-ChildItem ~\\.ssh # don't print keys", ""},
		{"escaped hash is text", "Write-Output a` #b", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ActionCommandDecision(tc.command, cwd, home); got != tc.want {
				t.Fatalf("ActionCommandDecision(%q) = %q, want %q", tc.command, got, tc.want)
			}
		})
	}
	for _, command := range []string{
		"Write-Output a` #; Get-Content ~\\.ssh\\id_ed25519",
		"echo a\\ #; head -c 4096 ~/.ssh/id_ed25519",
		"echo a\\ #; cat ~/.ssh/id_ed25519 | base64",
		"echo “ ; head -c 4096 ~/.ssh/id_ed25519 ; echo ”",
	} {
		if !ActionPrivateKeyRead(command, cwd, home) {
			t.Errorf("ActionPrivateKeyRead(%q) = false, want a key read", command)
		}
	}
	if ActionPrivateKeyRead("echo a\\ #; head -c 4096 ~/.ssh/id_ed25519.pub", cwd, home) {
		t.Error("a public key read is not a key read")
	}
}
