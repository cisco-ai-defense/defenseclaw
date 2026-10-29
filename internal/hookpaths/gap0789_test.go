// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"testing"
)

func TestGAP0789PrivateKeyReadInCompoundCommand(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	for _, tc := range []struct {
		name, command, cwd, home string
		block                    bool
	}{
		{"POSIX read first", `cat ~/.ssh/id_ed25519; echo done`, cwd, home, true},
		{"POSIX head read first", `head -c 4096 ~/.ssh/id_ed25519; echo done`, cwd, home, true},
		{"POSIX zero-byte head first", `head -c 0 ~/.ssh/id_ed25519; echo done`, cwd, home, true},
		{"POSIX read last", `echo hi; cat ~/.ssh/id_ed25519`, cwd, home, true},
		{"POSIX home variable", `cat "$HOME/.ssh/id_ed25519"; echo done`, cwd, home, true},
		{"POSIX ordinary read", `cat report.txt; echo done`, cwd, home, false},
		{"PowerShell read first", `Get-Content "$env:USERPROFILE\.ssh\id_ed25519"; Write-Output done`, `C:\Users\alice\project`, `C:\Users\alice`, true},
		{"PowerShell read last", `Write-Output done; Get-Content "$env:USERPROFILE\.ssh\id_ed25519"`, `C:\Users\alice\project`, `C:\Users\alice`, true},
		{"cmd read first", `type %USERPROFILE%\.ssh\id_ed25519 & echo done`, `C:\Users\alice\project`, `C:\Users\alice`, true},
		// GAP-0974: a pattern read operand that can select a key reads it.
		{"POSIX head glob read", `head -c 4096 ~/.ssh/id_*; echo`, cwd, home, true},
		{"POSIX cat glob read", `cat ~/.ssh/id_e*`, cwd, home, true},
		{"POSIX glob of public keys only", `cat ~/.ssh/*.pub`, cwd, home, false},
		{"Git Bash head glob read", `head -c 4096 ~/.ssh/id_*; echo`, `C:\Users\alice\project`, `C:\Users\alice`, true},
		{"PowerShell glob read", `Get-Content $env:USERPROFILE\.ssh\id_*`, `C:\Users\alice\project`, `C:\Users\alice`, true},
		{"Windows glob of public keys only", `head -c 4096 ~/.ssh/*.pub`, `C:\Users\alice\project`, `C:\Users\alice`, false},
		{"Windows ordinary read", `Get-Content .\report.txt; Write-Output done`, `C:\Users\alice\project`, `C:\Users\alice`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ActionPrivateKeyRead(tc.command, tc.cwd, tc.home)
			if got != tc.block {
				t.Fatalf("private-key proof = %v, want %v", got, tc.block)
			}
			if reason := ActionCommandDecision(tc.command, tc.cwd, tc.home); reason != "" {
				t.Fatalf("private-key read classified as persistence: %q", reason)
			}
		})
	}
}
