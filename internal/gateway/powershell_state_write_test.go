// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestR105WindowsPowerShellStateWriteSpellings: PowerShell spellings that
// empty, rename or overwrite DefenseClaw state are tamper.detector_state_write
// in action mode under every shell tool name (GAP-2414): Clear-Content and its
// alias clc, the ren alias of Rename-Item, a provider-path braced variable
// assignment (${C:\...} = 'x' writes the file) and a piped Out-File.
func TestR105WindowsPowerShellStateWriteSpellings(t *testing.T) {
	const connectorName = "r105-ps-state"
	installToolCallCorpusProfileConnector(t, connectorName, "default")
	const home = `C:\Users\Alice`
	resolved := map[string]string{}
	resolved["C:/Users/Alice/.defenseclaw"] = "C:/Users/Alice/.defenseclaw"
	for _, name := range []string{"config.yaml", "c.bak"} {
		value := "C:/Users/Alice/.defenseclaw/" + name
		resolved[value] = value
	}
	for _, tc := range []struct {
		command string
		block   bool
	}{
		{`Clear-Content $HOME\.defenseclaw\config.yaml`, true},
		{`clc $HOME\.defenseclaw\config.yaml`, true},
		{`Clear-Content -Path C:\Users\Alice\.defenseclaw\config.yaml`, true},
		{`ren $HOME\.defenseclaw\config.yaml c.bak`, true},
		{`${C:\Users\Alice\.defenseclaw\config.yaml} = 'x'`, true},
		{`${c:/Users/Alice/.defenseclaw/config.yaml} = ''`, true},
		{`${C:\Users\Alice\.defenseclaw\config.yaml} += 'x'`, true},
		{`'' | Out-File $HOME\.defenseclaw\config.yaml`, true},
		{`Set-Content $HOME\.defenseclaw\config.yaml ''`, true},
		{`Set-Content -Path $HOME\.defenseclaw\config.yaml -Value '' -Force`, true},
		{`sc $HOME\.defenseclaw\config.yaml x`, true},
		{`Rename-Item $HOME\.defenseclaw\config.yaml c.bak`, true},
		{`Rename-Item -Path $HOME\.defenseclaw\config.yaml -NewName c.bak -Force`, true},
		{`rni $HOME\.defenseclaw\config.yaml c.bak`, true},
		{`Move-Item $HOME\.defenseclaw\config.yaml $HOME\c.bak -Force`, true},
		{`Out-File -FilePath $HOME\.defenseclaw\config.yaml -InputObject ''`, true},
		{`[IO.File]::WriteAllText("$HOME\.defenseclaw\config.yaml", '')`, true},
		{`[System.IO.File]::WriteAllText('C:\Users\Alice\.defenseclaw\config.yaml', '')`, true},
		{`'' > $HOME\.defenseclaw\config.yaml`, true},
		{`Write-Output x > $env:USERPROFILE\.defenseclaw\config.yaml`, true},
		{`Clear-Content $env:USERPROFILE\.defenseclaw\config.yaml -Force`, true},
		{`Remove-Item -Recurse -Force $HOME\.defenseclaw`, true},
		{`Get-Date | Out-File $HOME\.defenseclaw\config.yaml`, true},
		{`$x = 'a'; $x | Set-Content $HOME\.defenseclaw\config.yaml`, true},
		{`if ($true) { '' > $HOME\.defenseclaw\config.yaml }`, true},
		{`[IO.File]::Delete("$HOME\.defenseclaw\config.yaml")`, true},
		{`[System.IO.File]::AppendAllText('C:\Users\Alice\.defenseclaw\config.yaml', 'x')`, true},
		{`Write-Output "$(Clear-Content $HOME\.defenseclaw\config.yaml)"`, true},
		{`Write-Output (clc $HOME\.defenseclaw\config.yaml)`, true},
		{"Get-ChildItem\n'' > $HOME\\.defenseclaw\\config.yaml", true},
		{`’’ > $HOME\.defenseclaw\config.yaml`, true},
		// Ordinary work stays allowed.
		{`Clear-Content $HOME\.defenseclaw\config.yaml -WhatIf`, false},
		{`Copy-Item $HOME\.defenseclaw\config.yaml backup.yaml`, false},
		{`[IO.File]::Copy("$HOME\.defenseclaw\config.yaml", "backup.yaml")`, false},
		{`[IO.File]::ReadAllText("$HOME\.defenseclaw\config.yaml")`, false},
		{`'x' > notes.txt; Get-Content $HOME\.defenseclaw\config.yaml`, false},
		{`git commit -m "doc: Clear-Content $HOME\.defenseclaw\config.yaml empties it"`, false},
		{"Get-ChildItem # '' > $HOME\\.defenseclaw\\config.yaml", false},
		{"cat > notes.md <<'EOF'\nTip: Clear-Content $HOME\\.defenseclaw\\config.yaml empties it\nEOF", false},
		{"@'\nren $HOME\\.defenseclaw\\config.yaml c.bak\n'@ | Set-Content notes.md", false},
		{`sc query defenseclaw`, false},
		{`Rename-Item -Path notes.txt -NewName notes2.txt`, false},
		{`Clear-Content .\notes.txt`, false},
		{`clc notes.txt`, false},
		{`ren notes.txt notes.bak`, false},
		{`${C:\Users\Alice\project\notes.txt} = 'x'`, false},
		{`'' | Out-File notes.txt`, false},
		{`Get-Content $HOME\.defenseclaw\config.yaml`, false},
		{`Write-Output ${C:\Users\Alice\.defenseclaw\config.yaml}`, false},
		{`$x = ${env:USERPROFILE}`, false},
		{`Set-Content notes.txt 'x'`, false},
		{`Rename-Item notes.txt notes2.txt`, false},
		{`[IO.File]::WriteAllText("$PWD\notes.txt", 'x')`, false},
		{`Get-Content $HOME\.defenseclaw\config.yaml | Out-File notes.txt`, false},
		{`Write-Output 'Clear-Content $HOME\.defenseclaw\config.yaml'`, false},
	} {
		for _, tool := range []string{"Bash", "shell_command", "PowerShell"} {
			args, _ := json.Marshal(map[string]string{"command": tc.command})
			input := actionfacts.Input{Tool: tool, Args: args, CWD: home + `\project`, ActiveHome: home}
			input.DialectHint = agentHookWindowsShellDialect(input)
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, LegacyText: string(args), Connector: connectorName,
				EnforcementCapable: true, ResolvedWriteTargets: resolved,
			})
			verdict := buildVerdict(findings, "tool_call")
			if got := verdict.Action == "block"; got != tc.block {
				t.Errorf("%s %s (dialect %q): action %q, want block=%t (findings %v)",
					tool, tc.command, input.DialectHint, verdict.Action, tc.block, findings)
			}
		}
	}
}
