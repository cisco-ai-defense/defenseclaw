// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestR105WindowsPowerShellStateWriteSpellings: PowerShell spellings that
// empty, rename or overwrite DefenseClaw state are tamper.detector_state_write
// in action mode under every shell tool name (GAP-2414): Clear-Content and its
// alias clc, the ren alias of Rename-Item, a provider-path braced variable
// assignment (${C:\...} = 'x' writes the file) and a piped Out-File.
// psManySteps is an ordinary script with many distinct output statements
// that name DefenseClaw and one state read (checker it14 B40).
var psManySteps = func() string {
	var parts []string
	for k := range 130 {
		parts = append(parts, `Write-Host "defenseclaw step `+strconv.Itoa(k)+`"`)
	}
	return strings.Join(parts, "; ") + `; Get-Content $HOME\.defenseclaw\config.yaml`
}()

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
		// Common parameters, stream redirects and a nested powershell
		// -Command keep the proof (checker it14 RV14-1 C04/P15 and class rows).
		{`Rename-Item $HOME\.defenseclaw\config.yaml c.bak -ErrorAction Stop`, true},
		{`Rename-Item $HOME\.defenseclaw\config.yaml c.bak -Force -ErrorAction Stop`, true},
		{`Rename-Item $HOME\.defenseclaw\config.yaml c.bak -Verbose`, true},
		{`Rename-Item -Path $HOME\.defenseclaw\config.yaml -NewName c.bak -ErrorAction SilentlyContinue`, true},
		{`Rename-Item -Path $HOME\.defenseclaw\config.yaml -NewName c.bak -WarningAction Ignore`, true},
		{`ren $HOME\.defenseclaw\config.yaml c.bak -ErrorAction Stop`, true},
		{`Set-Content $HOME\.defenseclaw\config.yaml x -ea 0`, true},
		{`Clear-Content $HOME\.defenseclaw\config.yaml -ea 0`, true},
		{`Clear-Content $HOME\.defenseclaw\config.yaml -ErrorAction:SilentlyContinue`, true},
		{`clc $HOME\.defenseclaw\config.yaml -ea 0`, true},
		{`Move-Item $HOME\.defenseclaw\config.yaml $HOME\c.bak -Verbose`, true},
		{`Remove-Item $HOME\.defenseclaw\config.yaml -ea 0`, true},
		{`Clear-Content $HOME\.defenseclaw\config.yaml 2>$null`, true},
		{`Set-Content $HOME\.defenseclaw\config.yaml x 2>$null`, true},
		{`Remove-Item $HOME\.defenseclaw\config.yaml 2>&1`, true},
		{`Remove-Item $HOME\.defenseclaw\config.yaml *>$null`, true},
		{`powershell -Command "Set-Content $HOME\.defenseclaw\config.yaml x"`, true},
		{`powershell -NoProfile -Command "Clear-Content $HOME\.defenseclaw\config.yaml"`, true},
		{`powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Remove-Item $HOME\.defenseclaw\config.yaml"`, true},
		{`pwsh -c "Rename-Item $HOME\.defenseclaw\config.yaml c.bak -ErrorAction Stop"`, true},
		// Ordinary work with the same parameters stays allowed.
		{`Rename-Item notes.txt notes2.txt -ErrorAction Stop`, false},
		{`Rename-Item -Path notes.txt -NewName notes2.txt -ErrorAction SilentlyContinue -Verbose`, false},
		{`Clear-Content .\notes.txt -ea 0`, false},
		{`Set-Content notes.txt x 2>$null`, false},
		{`Get-Content $HOME\.defenseclaw\config.yaml 2>$null`, false},
		{`Get-Content $HOME\.defenseclaw\config.yaml -ErrorAction Stop`, false},
		{`Copy-Item $HOME\.defenseclaw\config.yaml backup.yaml -Verbose`, false},
		{`powershell -Command "Get-Content $HOME\.defenseclaw\config.yaml"`, false},
		{`pwsh -NoProfile -c "Set-Content notes.txt x; Get-Content $HOME\.defenseclaw\config.yaml"`, false},
		{psManySteps, false},
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

// TestR105WindowsPowerShellStateReaderIsLinear: the PowerShell reading of the
// state-write proof stays linear on crafted input (block comments, braced
// variables, nested subexpressions and .NET calls) and still judges the
// state write that follows; past its bounds a state-naming command is the
// write (checker it14 RV14-2).
func TestR105WindowsPowerShellStateReaderIsLinear(t *testing.T) {
	const connectorName = "r105-ps-state-linear"
	installToolCallCorpusProfileConnector(t, connectorName, "default")
	const home = `C:\Users\Alice`
	resolved := map[string]string{}
	for _, value := range []string{"C:/Users/Alice/.defenseclaw", "C:/Users/Alice/.defenseclaw/config.yaml"} {
		resolved[value] = value
	}
	const size = 180 << 10
	for _, unit := range []string{"<#a#> ", "${a} ", "\"$(", "[IO.File]::WriteAllText(", "(", "@'\n'@\n", "x 2>$null; "} {
		for _, tail := range []string{"\nClear-Content $HOME\\.defenseclaw\\config.yaml", "\nRemove-Item $HOME\\.defenseclaw\\config.yaml"} {
			command := strings.Repeat(unit, size/len(unit)) + tail
			args, _ := json.Marshal(map[string]string{"command": command})
			input := actionfacts.Input{Tool: "PowerShell", Args: args, CWD: home + `\project`, ActiveHome: home,
				DialectHint: actionfacts.DialectPowerShell}
			start := time.Now()
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, LegacyText: string(args), Connector: connectorName,
				EnforcementCapable: true, ResolvedWriteTargets: resolved,
			})
			took := time.Since(start)
			if took > 3*time.Second {
				t.Errorf("unit %q: %d bytes judged in %s", unit, len(command), took)
			}
			if verdict := buildVerdict(findings, "tool_call"); verdict.Action != "block" {
				t.Errorf("unit %q tail %q: action %q, want block", unit, tail, verdict.Action)
			}
		}
	}
}
