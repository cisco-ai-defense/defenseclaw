// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"strings"
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
	const project = `C:\Users\Alice\project\notes.txt`
	const envelope = "*** Begin Patch`n*** Update File: C:/Users/Alice/.defenseclaw/config.yaml`n@@`n-a`n+b`n*** End Patch"
	api := &APIServer{}
	pwsh := func(body string) string {
		return `"C:\Program Files\PowerShell\7\pwsh.exe" -NoProfile -Command ` + "'" + body + "'"
	}
	// alternatives binds $p to n ordinary files named for DefenseClaw, one per
	// branch of an if / elseif chain, and to last in the else branch.
	alternatives := func(n int, last string) string {
		var chain strings.Builder
		for i := 0; i < n; i++ {
			keyword := "if"
			if i > 0 {
				keyword = " elseif"
			}
			fmt.Fprintf(&chain, `%s ($c%d) { $p = 'C:\Users\Alice\project\defenseclaw_note%d.txt' }`, keyword, i, i)
		}
		return `$p = '` + project + `'; ` + chain.String() + ` else { $p = '` + last + `' }; [IO.File]::WriteAllText($p, 'x')`
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
		{"self assignment keeps the binding", `$p = '` + state + `'; $p = $p; [IO.File]::WriteAllText($p, 'x')`, true},
		{"interpolated from a bound directory", `$d = 'C:\Users\Alice\.defenseclaw'; $p = "$d\config.yaml"; [IO.File]::WriteAllText($p, 'x')`, true},
		{"dead branch rebind to an ordinary file", `$p = '` + state + `'; if ($false) { $p = '` + project + `' }; [IO.File]::WriteAllText($p, 'x')`, true},
		{"live branch may rebind", `$p = '` + state + `'; if ($c) { $p = '` + project + `' }; [IO.File]::WriteAllText($p, 'x')`, true},
		{"live branch may bind the state", `$p = '` + project + `'; if ($c) { $p = '` + state + `' }; [IO.File]::WriteAllText($p, 'x')`, true},
		{"one else branch binds the state", `$p = '` + project + `'; if ($c) { $p = '` + state + `' } else { $p = '` + project + `' }; [IO.File]::WriteAllText($p, 'x')`, true},
		{"always-true branch binds the state", `$p = '` + project + `'; if ($true) { $p = '` + state + `' } else { $p = '` + project + `' }; [IO.File]::WriteAllText($p, 'x')`, true},
		{"loop binds the state after its write", `$p = '` + project + `'; foreach ($i in 1..2) { [IO.File]::WriteAllText($p, 'x'); $p = '` + state + `' }`, true},
		{"script block binds the state", `$p = '` + project + `'; 1..2 | ForEach-Object { [IO.File]::WriteAllText($p, 'x'); $p = '` + state + `' }`, true},
		{"command call in the condition", `$p = '` + project + `'; if (Test-Path $p) { $p = '` + state + `' }; [IO.File]::WriteAllText($p, 'x')`, true},
		{"command call in the condition, both branches rebind", `$p = '` + state + `'; if (foo) { $p = '` + project + `' } else { $p = '` + project + `' }; [IO.File]::WriteAllText($p, 'x')`, false},
		{"elseif chain, last branch binds the state", `$p = '` + project + `'; if ($a) { $p = '` + project + `' } elseif ($b) { $p = '` + state + `' } else { $p = '` + project + `' }; [IO.File]::WriteAllText($p, 'x')`, true},
		{"multi-line if and else both rebind", "$p = '" + state + "'\nif ($c) {\n  $p = '" + project + "'\n}\nelse {\n  $p = '" + project + "'\n}\n[IO.File]::WriteAllText($p, 'x')", false},
		{"dead branch binds the state", `$p = '` + project + `'; if ($false) { $p = '` + state + `' }; [IO.File]::WriteAllText($p, 'x')`, false},
		{"write in a dead branch", `$p = '` + state + `'; if ($false) { [IO.File]::WriteAllText($p, 'x') }; [IO.File]::WriteAllText('` + project + `', 'x')`, false},
		{"dead loop write", `$p = '` + state + `'; while ($false) { [IO.File]::WriteAllText($p, 'x') }`, false},
		{"both branches rebind", `$p = '` + state + `'; if ($c) { $p = '` + project + `' } else { $p = '` + project + `' }; [IO.File]::WriteAllText($p, 'x')`, false},
		{"always-true branch rebinds", `$p = '` + state + `'; if ($true) { $p = '` + project + `' }; [IO.File]::WriteAllText($p, 'x')`, false},
		{"patch text printed, not run", `$patch = "` + envelope + `"; Write-Output '--codex-run-as-apply-patch' $patch`, false},
		{"patch text echoed with the flag", `$patch = "` + envelope + `"; echo --codex-run-as-apply-patch $patch`, false},
		{"dead branch binds and writes the state", `if ($false) { $p = '` + state + `'; [IO.File]::WriteAllText($p, 'x') }; [IO.File]::WriteAllText('` + project + `', 'x')`, false},
		{"dead else binds and writes the state", `if ($true) { [IO.File]::WriteAllText('` + project + `', 'x') } else { $p = '` + state + `'; [IO.File]::WriteAllText($p, 'x') }`, false},
		{"dead loop binds and writes the state", `while ($false) { $p = '` + state + `'; [IO.File]::WriteAllText($p, 'x') }`, false},
		{"live branch binds and writes the state", `if ($c) { $p = '` + state + `'; [IO.File]::WriteAllText($p, 'x') }`, true},
		{"patch flag on an unrelated program", `$patch = "` + envelope + `"; & 'C:\Windows\System32\whoami.exe' --codex-run-as-apply-patch $patch`, false},
		{"patch flag echoed by cmd", `$patch = "` + envelope + `"; & 'C:\Windows\System32\cmd.exe' /c echo --codex-run-as-apply-patch $patch`, false},
		{"patch run by codex behind cmd", `$patch = "` + envelope + `"; & 'C:\Windows\System32\cmd.exe' /c 'C:\dc\codex.exe' --codex-run-as-apply-patch $patch`, true},
		{"patch run by codex behind Start-Process", `$patch = "` + envelope + `"; Start-Process 'C:\dc\codex.exe' -ArgumentList '--codex-run-as-apply-patch', $patch`, true},
		{"eight alternatives, state last", alternatives(7, state), true},
		{"nine alternatives, state last", alternatives(8, state), true},
		{"twelve alternatives, state last", alternatives(11, state), true},
		{"eight ordinary alternatives", alternatives(7, `C:\Users\Alice\project\defenseclaw_last.txt`), false},
		{"values carried around a loop", `$a = '` + state + `'; $b = '` + project + `defenseclaw1'; $c = '` + project + `defenseclaw2'; $d = '` + project + `defenseclaw3'; foreach ($i in 1..4) { [IO.File]::WriteAllText($d, 'x'); $d = $c; $c = $b; $b = $a }`, true},
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
