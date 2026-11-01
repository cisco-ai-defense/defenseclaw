// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// PowerShell 7 ParseInput reads the tail in every row as a Remove-Item command.
// Each spelling must retain that command in both connector and policy modes.
func TestGAP0343PowerShellGluedArgumentAndStopParsingTail(t *testing.T) {
	const home = `C:\Users\Alice`
	const tail = `Remove-Item -Recurse -Force C:\`
	for _, row := range []struct{ name, prefix string }{
		{"double quote in word", `Write-Output a"b"#; `},
		{"single quote in word", `Write-Output a'b'#; `},
		{"right bracket in word", `Write-Output a]#; `},
		{"left bracket in word", `Write-Output a[#; `},
		{"type name in argument", `Write-Output [int]#; `},
		{"format argument", `git log -1 --format="%h"#; `},
		{"path with bracket", `Get-ChildItem .\a[1]#; `},
		{"call target with equals", `& $x=#; `},
		{"glued call target with equals", `&$x=#; `},
		{"argument variable with equals", `Write-Output $x=#; `},
		{"glued block opener", `Write-Output a"b"<#x#>; `},
		{"bracket and block opener", `Write-Output a]<#x#>; `},
		{"quoted only block comment", `Write-Output "a"<#x#>; `},
		{"equals before stop parsing lookalike", `cmd /c echo a=--% ; `},
		{"comma before stop parsing lookalike", `cmd /c echo a,--% ; `},
		{"stop parsing then chain", `cmd.exe /c echo --% a && `},
		{"stop parsing then or chain", `cmd.exe /c echo --% a || `},
		{"stop parsing then pipe", `cmd.exe /c echo --% a | `},
		{"stop parsing then glued pipe", `cmd.exe /c echo --% a|`},
		{"quoted pipe in stop parsing argument", `cmd.exe /c echo --% "a | b" | `},
		{"quoted chain in stop parsing argument", `cmd.exe /c echo --% "a && b" && `},
		{"mixed quote inside array command", `$x = @(Write-Output a"b"#; Write-Output ok); `},
		{"bracket inside array command", `$x = @(Write-Output a]#; Write-Output ok); `},
		{"block marker inside array command", `$x = @(Write-Output a"b"<#x#>; Write-Output ok); `},
	} {
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
						Input: actionfacts.Input{Tool: tool, Command: row.prefix + tail,
							CWD: home + `\project`, ActiveHome: home, DialectHint: actionfacts.DialectPowerShell},
						Connector: connector, EnforcementCapable: true,
					})
					if got := buildVerdict(findings, "tool_call").Action; got != guardrailActionBlock ||
						findingWithID(findings, "CMD-RM-RF") == nil {
						t.Fatalf("action=%s findings=%v, want the destructive tail blocked", got, findingIDs(findings))
					}
				})
			}
		}
	}
}
