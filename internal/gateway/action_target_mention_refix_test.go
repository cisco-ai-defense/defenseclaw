// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func TestR104WindowsActionTargetMentionReview(t *testing.T) {
	const connector = "r104-windows-target-review"
	const home = `C:\Users\b00`
	installToolCallCorpusProfileConnector(t, connector, "default")
	for _, tc := range []struct {
		name, command string
		block         bool
	}{
		{"Select-Object calculated write", `Get-ChildItem C:\Users\b00\.ssh | Select-Object @{e={Set-Content C:\Users\b00\.ssh\authorized_keys marker}}`, true},
		{"Select-Object property write", `Get-ChildItem C:\Users\b00\.ssh | Select-Object -Property {Add-Content -Path C:\Users\b00\.ssh\authorized_keys -Value marker}`, true},
		{"nested Add-Content", `Test-Path (Add-Content -Path C:\Users\b00\.ssh\authorized_keys -Value marker -PassThru)`, true},
		{"nested .NET write", `[IO.File]::ReadAllText([IO.File]::AppendAllText('C:/Users/b00/.ssh/authorized_keys','marker'))`, true},
		{"protected glob", `Copy-Item payload C:\Users\b00\.ssh\authorized_k*`, true},
		{"ordinary glob", `Copy-Item payload C:\Users\b00\.ssh\*.pub`, false},
		{"directory listing plain", `Get-ChildItem C:\Users\b00\.ssh`, false},
		{"directory listing pipeline", `Get-ChildItem C:\Users\b00\.ssh | Format-Table Name`, true},
		{"directory listing scriptblock", `foreach ($n in Get-ChildItem C:\Users\b00\.ssh) { Write-Output $n.Name }`, true},
		{"directory navigation", `Push-Location C:\Users\b00\.ssh; Get-ChildItem; Pop-Location`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args, err := json.Marshal(map[string]string{"command": tc.command})
			if err != nil {
				t.Fatal(err)
			}
			input := actionfacts.Input{Tool: "Bash", Args: args, Command: tc.command,
				CWD: `C:\work`, ActiveHome: home, DialectHint: actionfacts.DialectPowerShell}
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, LegacyText: string(args), Connector: connector, EnforcementCapable: true,
			})
			blocked := buildVerdict(findings, "tool_call").Action == guardrailActionBlock
			if blocked != tc.block {
				t.Errorf("blocked=%v, want %v: %v", blocked, tc.block, FindingStrings(findings))
			}
		})
	}
}
