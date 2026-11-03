// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// These four-cell rows pin PowerShell's token and comment boundaries around
// balanced values. ParseInput on PowerShell 7 confirms the executable tail in
// every blocking row and confirms comment text stays inert in the allow rows.
func TestGAP0343PowerShellReaderRound2(t *testing.T) {
	const home = `C:\Users\Alice`
	rows := []struct {
		name, command string
		block         bool
	}{
		{"M4 doubled quote", "$a = @(\"a \"\" ) b\", 1); Remove-Item -Recurse -Force C:\\", true},
		{"M5 subexpression in double quote", "$a = @(\"$(Write-Output \"a } b\")\"); Remove-Item -Recurse -Force C:\\", true},
		{"M8 here-string in value", "$a = @(@'\n' )\n'@); Remove-Item -Recurse -Force C:\\", true},
		{"M9 braced-variable frame", "${a)b} = 1; Remove-Item -Recurse -Force C:\\", true},
		{"M10 mismatched closer", "$a = @{ a = 1) ; Remove-Item -Recurse -Force C:\\", false},
		{"M11 backtick in code", "$x = $(Write-Output `) ); Remove-Item -Recurse -Force C:\\", true},
		{"M12 backtick in double quote", "$a = @(\"a `\") b\", 1); Remove-Item -Recurse -Force C:\\", true},
		{"M14 stop parsing in splitter", "cmd.exe --% ) | Remove-Item -Recurse -Force C:\\", true},
		{"M15 here-string line start", "$a = @(@'\nmid '@ rest )\n'@); Remove-Item -Recurse -Force C:\\", true},
		{"M16 hash in argument", "$x = $(git log -1 --format=#%h); Remove-Item -Recurse -Force C:\\", true},
		{"M19 first block close", "$a = @(<# <# #> 1); Remove-Item -Recurse -Force C:\\ # #>", true},
		{"M20 stop parsing in matcher", "$x = $(cmd.exe --% ) | Out-Null); Remove-Item -Recurse -Force C:\\", true},
		{"M21 braced-variable opener", "${a\"b} = 1; Remove-Item -Recurse -Force C:\\", true},
		{"probe nested block comment", "$a = @(<# <# #> 1); Remove-Item -Recurse -Force C:\\ # #>", true},
		{"probe stop-parsing pipe", "cmd.exe /c echo --% a | Remove-Item -Recurse -Force C:\\", true},
		{"probe quoted stop-parsing pipe", "cmd.exe /c echo --% \"a | b\" | Remove-Item -Recurse -Force C:\\", true},
		{"probe eq-hash argument", "$x = $(git log -1 --format=#%h); Remove-Item -Recurse -Force C:\\", true},
		{"probe quote-hash comment", "$a = @('x'# don't\n 2)\nRemove-Item -Recurse -Force C:\\", true},
		{"probe type-hash comment", "$a = @([int]# ) ; Remove-Item C:\\decoy\n 2)\nWrite-Output ok", false},
		{"probe comment after value", "$a = @(1)# ; Remove-Item -Recurse -Force C:\\decoy\nWrite-Output ok", false},
		{"probe comment after hashtable", "$h = @{ a = 1 }# ; Remove-Item -Recurse -Force C:\\decoy\nWrite-Output ok", false},
		{"probe comment after assignment equals", "$x =# ; Remove-Item -Recurse -Force C:\\decoy\nWrite-Output ok", false},
		{"probe block comment after assignment equals", "$x =<# note #>1; Remove-Item -Recurse -Force C:\\", true},
	}
	for _, row := range rows {
		for _, connector := range []string{"claudecode", "codex"} {
			for _, managed := range []bool{false, true} {
				cell := "/per-user"
				if managed {
					cell = "/managed"
				}
				t.Run(row.name+"/"+connector+cell, func(t *testing.T) {
					ctx := context.Background()
					if managed {
						ctx = withManagedHookPeer(ctx, managedHookPeer{Home: home})
					}
					tool := "PowerShell"
					if connector == "codex" {
						tool = "exec_command"
					}
					findings := dispatchTrustedAction(ctx, trustedActionRequest{
						Input: actionfacts.Input{Tool: tool, Command: row.command, CWD: home + `\project`,
							ActiveHome: home, DialectHint: actionfacts.DialectPowerShell},
						Connector: connector, EnforcementCapable: true,
					})
					blocked := buildVerdict(findings, "tool_call").Action == guardrailActionBlock
					if blocked != row.block {
						t.Fatalf("blocked=%t, want %t; findings=%v", blocked, row.block, findingIDs(findings))
					}
					if row.block && findingWithID(findings, "CMD-RM-RF") == nil {
						t.Fatalf("destructive tail missing: %v", findingIDs(findings))
					}
				})
			}
		}
	}
}
