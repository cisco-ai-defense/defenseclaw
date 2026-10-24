// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// W24 loop round 3 (balanced defaults), end to end: a parenthesized
// PowerShell copy loop and argument text that only contains a key name are
// not SSH persistence; quoted or variable data does not run an exported
// function or a scriptblock literal. Protected and runnable forms still block.
func TestTrustedActionW24DataIsNotEvidence(t *testing.T) {
	t.Run("Windows persistence", func(t *testing.T) {
		const wcwd, whome = `C:\Users\alice\project`, `C:\Users\alice`
		for _, tc := range []struct {
			name, connector, tool, command string
			block                          bool
		}{
			{"parenthesized copy loop", "codex", "exec_command", `foreach ($f in (Get-ChildItem *.txt)) { Copy-Item $f out }`, false},
			{"subexpression copy loop", "claudecode", "Bash", `foreach ($f in $(Get-ChildItem *.txt)) { Copy-Item $f out }`, false},
			{"script with key text in an argument", "claudecode", "Bash", `pwsh -File .\build.ps1 -Case id_rsa-smoke`, false},
			{"ForEach-Object copy loop", "codex", "exec_command", `Get-ChildItem *.txt | ForEach-Object { Copy-Item $_ out }`, false},
			{"ForEach-Object write to the loop value", "codex", "exec_command", `Get-ChildItem *.txt | ForEach-Object { Set-Content $_ key }`, true},
			{"parenthesized copy loop to the protected file", "codex", "exec_command", `foreach ($f in (Get-ChildItem *.txt)) { Copy-Item $f C:\Users\alice\.ssh\authorized_keys }`, true},
			{"script with a key path", "codex", "exec_command", `pwsh -File .\x.ps1 -Key "$keys\id_rsa"`, true},
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
	})
	t.Run("POSIX persistence", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("POSIX rows need a POSIX home")
		}
		home, cwd := r104ReviewHome(t)
		if err := os.WriteFile(filepath.Join(cwd, "run.sh"), []byte("echo ok\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			name, command string
			block         bool
		}{
			{"script with key text in an argument", `bash run.sh --case id_rsa-smoke`, false},
			{"script with a key path", `bash run.sh "$KEYDIR/id_rsa"`, true},
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
	})
	t.Run("rules", func(t *testing.T) {
		const connector = "w24-data-test"
		installDefaultProfileConnector(t, connector)
		for _, tt := range []struct {
			name, command string
			dialect       actionfacts.Dialect
			block         bool
		}{
			{"grep pattern names the function", "f() { rm -rf /; }; export -f f; /bin/grep -F 'bash f' README.md", actionfacts.DialectPOSIX, false},
			{"git message names the function", "f() { rm -rf /; }; export -f f; git commit -m 'call bash f'", actionfacts.DialectPOSIX, false},
			{"interpreter inline code calls the function", `f() { rm -rf /; }; export -f f; python3 -c "import os; os.system('bash -c f')"`, actionfacts.DialectPOSIX, true},
			{"variable in a Write-Output value", `{ Remove-Item -Recurse -Force C:\ } | Write-Output "report$year.txt"`, actionfacts.DialectPowerShell, false},
			{"variable property expression", `{ Remove-Item -Recurse -Force C:\ } | Format-Table $p`, actionfacts.DialectPowerShell, true},
		} {
			t.Run(tt.name, func(t *testing.T) {
				cwd, home := "/repo", "/home/alice"
				if tt.dialect == actionfacts.DialectPowerShell {
					cwd, home = `C:\repo`, `C:\Users\alice`
				}
				findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
					Input: actionfacts.Input{Tool: "shell", Command: tt.command, CWD: cwd,
						ActiveHome: home, DialectHint: tt.dialect},
					LegacyText: tt.command, Connector: connector, EnforcementCapable: true,
				})
				finding := findingWithID(findings, "CMD-RM-RF")
				if enforced := finding != nil && finding.contributesToEnforcement(); enforced != tt.block {
					t.Errorf("CMD-RM-RF enforced=%v, want %v: %v", enforced, tt.block, FindingStrings(findings))
				}
			})
		}
	})
}
