// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"fmt"
	"path/filepath"
	"slices"
	"testing"
)

// rel-1-0-10:GAP-0004 (rel-1-0-4:GAP-1717): Codex on Windows, started in the
// home folder, was denied a cat here-document whose body holds the
// apply_patch banner (*** Begin Patch) as an authorized-keys write, because
// the *** word of the body read as a glob that selects .ssh. The body is
// data. The same call through the Claude Code (Git Bash) route, a benign
// body and echo * stay allowed; every write to a key file, in PowerShell,
// cmd or Git Bash spelling, keeps its block in every profile.
func TestGAP0004WindowsHereDocBannerAtHomeCodex(t *testing.T) {
	gap0004WindowsCells(t, "codex")
}

func TestGAP0004WindowsHereDocBannerAtHomeClaudeCode(t *testing.T) {
	gap0004WindowsCells(t, "claudecode")
}

func gap0004WindowsCells(t *testing.T, connectorName string) {
	home, _ := shellProtectedFileHome(t)
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	notes := filepath.Join(home, "project", "notes.txt")
	const rule = "persistence.ssh_authorized_keys_command"
	rows := []struct {
		name, command string
		block         bool
	}{
		{"banner heredoc (GAP-0004 payload)", "cat <<\"EOT\"\n*** Begin Patch\n*** End Patch\nEOT", false},
		{"banner heredoc, unquoted delimiter", "cat <<EOT\n*** Begin Patch\n*** End Patch\nEOT", false},
		{"benign heredoc", "cat <<\"EOT\"\nhello world\nsecond line\nEOT", false},
		{"echo star", `echo "*"`, false},
		{"PowerShell Add-Content to the keys file", fmt.Sprintf("Add-Content -Path '%s' -Value marker", keys), true},
		{"PowerShell Set-Content to the keys file", fmt.Sprintf("Set-Content -Path '%s' -Value marker", keys), true},
		{"PowerShell Out-File to the keys file", fmt.Sprintf("'marker' | Out-File -Append -FilePath '%s'", keys), true},
		{"PowerShell Copy-Item onto the keys file", fmt.Sprintf("Copy-Item -Path '%s' -Destination '%s'", notes, keys), true},
		{"PowerShell Move-Item onto the keys file", fmt.Sprintf("Move-Item -Path '%s' -Destination '%s'", notes, keys), true},
		{"PowerShell $HOME spelling", `Add-Content -Path $HOME\.ssh\authorized_keys -Value marker`, true},
		{"administrators_authorized_keys", `Add-Content -Path C:\ProgramData\ssh\administrators_authorized_keys -Value marker`, true},
		{"cmd copy onto the keys file", `cmd /c copy notes.txt %USERPROFILE%\.ssh\authorized_keys`, true},
		{"heredoc written to the keys file", "cat <<EOT > ~/.ssh/authorized_keys\n*** Begin Patch\nEOT", true},
	}
	for _, row := range rows {
		for _, cell := range []string{"default", "permissive", "strict", "managed"} {
			posture, managed := cell, false
			if cell == "managed" {
				posture, managed = "default", true
			}
			t.Run(fmt.Sprintf("%s %s %s", connectorName, cell, row.name), func(t *testing.T) {
				action, rules := shellProtectedFileRoute(t, home, home, connectorName, posture, managed, row.command)
				if row.block {
					if action != "block" || !slices.Contains(rules, rule) {
						t.Fatalf("action = %q rules = %v, want block by %s", action, rules, rule)
					}
					return
				}
				if action != "allow" {
					t.Fatalf("action = %q rules = %v, want allow", action, rules)
				}
			})
		}
	}
}
