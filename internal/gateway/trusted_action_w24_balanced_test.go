// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// W24 loop round 2 (balanced defaults): ordinary script launches (GAP-1010)
// and copy loops (GAP-1012) are not SSH persistence on any route, while a
// protected or computed destination still blocks.
func TestTrustedActionW24ScriptsAndCopyLoopsAreNotPersistence(t *testing.T) {
	home, cwd := r104ReviewHome(t)
	for _, dir := range []string{filepath.Join(cwd, "copy")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{"regular.txt": "regular\n", "run.sh": "echo ok\n"} {
		if err := os.WriteFile(filepath.Join(cwd, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name, command string
		block         bool
	}{
		{"GAP-1012 copy loop", `for f in regular.txt; do cp "$f" copy/; done; echo ok > second-report.txt`, false},
		{"GAP-1012 glob copy loop", `for f in *.txt; do cp "$f" copy/; done`, false},
		{"GAP-1010 shell script with arguments", `bash run.sh test`, false},
		{"GAP-1010 direct script with arguments", `./run.sh test`, false},
		{"loop value is a protected link", `for f in regular.txt alias; do echo key >> "$f"; done`, true},
		{"script launch with a protected redirect", `bash run.sh test >> ~/.ssh/authorized_keys`, true},
		{"copy loop to a computed destination", `for f in *.txt; do cp "$f" "$dest"; done`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for i, blocked := range r104ReviewProtectedWrite(t, tc.command, cwd, home) {
				if blocked != tc.block {
					t.Errorf("proof route %d blocked=%t, want %t", i, blocked, tc.block)
				}
			}
			input := actionfacts.Input{Tool: "Bash", Command: tc.command, CWD: cwd, ActiveHome: home,
				DialectHint: actionfacts.DialectPOSIX}
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, Connector: "claudecode", EnforcementCapable: true,
			})
			finding := findingWithID(findings, "persistence.ssh_authorized_keys_command")
			if got := finding != nil && finding.contributesToEnforcement(); got != tc.block {
				t.Fatalf("persistence blocked=%v, want %v: %v", got, tc.block, FindingStrings(findings))
			}
		})
	}
	const wcwd, whome = `C:\Users\alice\project`, `C:\Users\alice`
	for _, tc := range []struct {
		name, connector, tool, command string
		block                          bool
	}{
		{"GAP-1010 native PowerShell script", "claudecode", "Bash", `pwsh.exe -NoProfile -ExecutionPolicy Bypass -File C:/dc-test/t9-a4w1-sec/scripts/t9s-webhook-case.ps1 -Case missing-dry -Source native`, false},
		{"GAP-1010 call operator script", "codex", "exec_command", `& .\build.ps1 -Configuration Release`, false},
		{"GAP-1010 Git Bash script", "claudecode", "Bash", `bash run.sh test`, false},
		{"GAP-1012 PowerShell copy loop", "codex", "exec_command", `foreach ($f in 'regular.txt') { Copy-Item $f copy }`, false},
		{"script with the protected file as an argument", "codex", "exec_command", `pwsh -File .\x.ps1 -Target $env:USERPROFILE\.ssh\authorized_keys`, true},
		{"copy to a computed destination", "codex", "exec_command", `Copy-Item src $dest`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := actionfacts.Input{Tool: agentHookTrustedActionTool(tc.connector, tc.tool, "windows"),
				Command: tc.command, CWD: wcwd, ActiveHome: whome}
			input.DialectHint = selectWindowsShellDialect(input.Tool, input.Command, input)
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, Connector: tc.connector, EnforcementCapable: true,
			})
			finding := findingWithID(findings, "persistence.ssh_authorized_keys_command")
			if got := finding != nil && finding.contributesToEnforcement(); got != tc.block {
				t.Fatalf("persistence blocked=%v, want %v: %v", got, tc.block, FindingStrings(findings))
			}
		})
	}
}
