// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// A PowerShell call that binds the DefenseClaw state path (or a patch
// envelope naming it) to a variable and writes through the variable is the
// same mutation as writing the literal: the proof reads the bound value, so
// observe mode refuses it like the literal spelling.
func TestPowerShellBoundValueStateWriteIsProvenInEveryMode(t *testing.T) {
	const connectorName = "ps-bound-state"
	installToolCallCorpusProfileConnector(t, connectorName, "default")
	const home = `C:\Users\Alice`
	resolved := map[string]string{}
	for _, value := range []string{"C:/Users/Alice/.defenseclaw", "C:/Users/Alice/.defenseclaw/config.yaml"} {
		resolved[value] = value
	}
	const state = `C:\Users\Alice\.defenseclaw\config.yaml`
	const envelope = "*** Begin Patch`n*** Update File: C:/Users/Alice/.defenseclaw/config.yaml`n@@`n-a`n+b`n*** End Patch"
	api := &APIServer{}
	pwsh := func(body string) string {
		return `"C:\Program Files\PowerShell\7\pwsh.exe" -NoProfile -Command ` + "'" + body + "'"
	}
	for _, tc := range []struct {
		name, command string
		block         bool
	}{
		{"literal write", `[System.IO.File]::WriteAllText('` + state + `', 'x')`, true},
		{"bound write", `$path = '` + state + `'; $text = 'x'; [System.IO.File]::WriteAllText($path, $text, [System.Text.UTF8Encoding]::new($false))`, true},
		{"bound write in pwsh", pwsh(`$p = ''` + state + `''; [IO.File]::WriteAllText($p, ''x'')`), true},
		{"bound double-quoted", `$p = "` + state + `"; [IO.File]::AppendAllText($p, "x")`, true},
		{"bound braced", `$p = '` + state + `'; [IO.File]::WriteAllText(${p}, 'x')`, true},
		{"bound twice", `$a = '` + state + `'; $b = $a; [IO.File]::Delete($b)`, true},
		{"bound Set-Content in pwsh", pwsh(`$p = ''` + state + `''; Set-Content -LiteralPath $p -Value x`), true},
		{"bound patch run by the codex binary", `$patch = "` + envelope + `"; & 'C:\dc\codex.exe' --codex-run-as-apply-patch $patch`, true},
		{"bound patch run by apply_patch", `$patch = "` + envelope + `"; apply_patch $patch`, true},
		{"bound patch in pwsh", pwsh(`$patch = "` + envelope + `"; & ''C:\dc\codex.exe'' --codex-run-as-apply-patch $patch`), true},
		{"bound read", `$p = '` + state + `'; [IO.File]::ReadAllText($p)`, false},
		{"bound read in pwsh", pwsh(`$p = ''` + state + `''; if (Test-Path -LiteralPath $p) { Get-Content -LiteralPath $p -Raw }`), false},
		{"bound project write", `$p = 'C:\Users\Alice\project\notes.txt'; [IO.File]::WriteAllText($p, 'x')`, false},
		{"rebound before the write", `$p = '` + state + `'; $p = 'C:\Users\Alice\project\notes.txt'; [IO.File]::WriteAllText($p, 'x')`, false},
		{"state path as the written text", `$p = '` + state + `'; Set-Content -LiteralPath C:\Users\Alice\project\notes.txt -Value $p`, false},
		{"bound project patch", `$patch = "*** Begin Patch` + "`n" + `*** Update File: C:/Users/Alice/project/a.txt` + "`n" + `@@` + "`n" + `-a` + "`n" + `+b` + "`n" + `*** End Patch"; apply_patch $patch`, false},
	} {
		for _, managed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/managed=%t", tc.name, managed), func(t *testing.T) {
				args, _ := json.Marshal(map[string]string{"command": tc.command})
				input := actionfacts.Input{Tool: "shell_command", Args: args, CWD: home + `\project`, ActiveHome: home}
				input.DialectHint = agentHookWindowsShellDialect(input)
				findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
					Input: input, LegacyText: string(args), Connector: connectorName,
					EnforcementCapable: true, ResolvedWriteTargets: resolved, ProtectedHomeHook: managed,
				})
				verdict := buildVerdict(findings, "tool_call")
				if got := verdict.Action == "block"; got != tc.block {
					t.Fatalf("action %q, want block=%t (findings %v)", verdict.Action, tc.block, findingIDs(findings))
				}
				if got := api.provenActiveStateMutation(t.Context(), verdict); got != tc.block {
					t.Fatalf("observe-mode hard block=%t, want %t", got, tc.block)
				}
			})
		}
	}
}
