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
	// chain binds the variable name to ordinary files named for DefenseClaw,
	// one per branch of an if / elseif chain of n branches (the state file in
	// branch protectedAt when it is not -1), and to last in the else branch;
	// then it runs tail.
	chain := func(name string, n int, last string, protectedAt int, tail string) string {
		var branches strings.Builder
		for i := 0; i < n; i++ {
			keyword := "if"
			if i > 0 {
				keyword = " elseif"
			}
			value := fmt.Sprintf(`C:\Users\Alice\project\defenseclaw_note%d`, i)
			if i == protectedAt {
				value = state
			}
			fmt.Fprintf(&branches, `%s ($c%d) { $%s = '%s' }`, keyword, i, name, value)
		}
		return `$` + name + ` = '` + project + `'; ` + branches.String() + ` else { $` + name + ` = '` + last + `' }; ` + tail
	}
	// alternatives binds $p in n branches and writes it, then runs extra.
	alternatives := func(n int, last string, protectedAt int, extra string) string {
		return chain("p", n, last, protectedAt, `[IO.File]::WriteAllText($p, 'x')`+extra)
	}
	const ordinaryLast = `C:\Users\Alice\project\defenseclaw_last.txt`
	const (
		readState      = `; [IO.File]::ReadAllText('` + state + `')`
		unusedBinding  = `; $q = '` + state + `'`
		stateAsContent = `; $s = '` + state + `'; Set-Content -LiteralPath ` + project + ` -Value $s`
	)
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
		{"patch run by quoted codex and flag behind cmd", `$patch = "` + envelope + `"; & 'C:\Windows\System32\cmd.exe' /c 'C:\dc\codex.exe --codex-run-as-apply-patch' $patch`, true},
		{"patch run by codex with a spaced path behind cmd", `$patch = "` + envelope + `"; & cmd.exe /c '"C:\Program Files\dc\codex.exe" --codex-run-as-apply-patch' $patch`, true},
		{"patch run by codex started by cmd start", `$patch = "` + envelope + `"; & cmd.exe /c 'start /b C:\dc\codex.exe --codex-run-as-apply-patch' $patch`, true},
		{"patch run by codex in one expanded cmd command string", `$patch = "` + envelope + `"; & cmd.exe /c "C:\dc\codex.exe --codex-run-as-apply-patch $patch"`, true},
		{"patch run by codex behind cmd start with a title", `$patch = "` + envelope + `"; & cmd.exe /d /s /c 'start /b "" C:\dc\codex.exe --codex-run-as-apply-patch' $patch`, true},
		{"patch run by codex behind cmd start with option values", `$patch = "` + envelope + `"; & cmd.exe /c 'start /node 0 /affinity 3 C:\dc\codex.exe --codex-run-as-apply-patch' $patch`, true},
		{"patch run by codex behind cmd start with a title and options", `$patch = "` + envelope + `"; & cmd.exe /c 'start "job" /b /d C:\dc C:\dc\codex.exe --codex-run-as-apply-patch' $patch`, true},
		{"patch run by codex behind cmd start with a title after the options", `$patch = "` + envelope + `"; & cmd.exe /c 'start /b "job" C:\dc\codex.exe --codex-run-as-apply-patch' $patch`, true},
		{"patch run by codex behind a true cmd if", `$patch = "` + envelope + `"; & cmd.exe /c 'if 1==1 C:\dc\codex.exe --codex-run-as-apply-patch' $patch`, true},
		{"patch run by codex behind cmd if not exist", `$patch = "` + envelope + `"; & cmd.exe /c 'if not exist C:\none C:\dc\codex.exe --codex-run-as-apply-patch' $patch`, true},
		{"patch run by codex behind cmd if with an operator word", `$patch = "` + envelope + `"; & cmd.exe /c 'if /i a EQU A C:\dc\codex.exe --codex-run-as-apply-patch' $patch`, true},
		{"patch run by codex behind cmd if and start", `$patch = "` + envelope + `"; & cmd.exe /c 'if errorlevel 0 start /b C:\dc\codex.exe --codex-run-as-apply-patch' $patch`, true},
		{"patch run by codex in a cmd else", `$patch = "` + envelope + `"; & cmd.exe /c 'if 1==2 (echo no) else C:\dc\codex.exe --codex-run-as-apply-patch' $patch`, true},
		{"patch run by codex in a cmd for loop", `$patch = "` + envelope + `"; & cmd.exe /c 'for %i in (1) do C:\dc\codex.exe --codex-run-as-apply-patch' $patch`, true},
		{"cmd start of another program lists codex and the flag", `$patch = "` + envelope + `"; & cmd.exe /c 'start /b whoami.exe C:\dc\codex.exe --codex-run-as-apply-patch' $patch`, false},
		{"cmd start titled with the codex name starts another program", `$patch = "` + envelope + `"; & cmd.exe /c 'start "C:\dc\codex.exe" /b whoami.exe --codex-run-as-apply-patch' $patch`, false},
		{"cmd start of cmd echoes the codex name", `$patch = "` + envelope + `"; & cmd.exe /c 'start /b cmd.exe /c echo C:\dc\codex.exe --codex-run-as-apply-patch' $patch`, false},
		{"cmd if runs another program that lists codex and the flag", `$patch = "` + envelope + `"; & cmd.exe /c 'if 1==1 whoami.exe C:\dc\codex.exe --codex-run-as-apply-patch' $patch`, false},
		{"patch run by codex behind cmd call", `$patch = "` + envelope + `"; & cmd.exe /c 'call C:\dc\codex.exe --codex-run-as-apply-patch' $patch`, true},
		{"patch run by codex after another cmd command", `$patch = "` + envelope + `"; & cmd.exe /c 'echo hi & C:\dc\codex.exe --codex-run-as-apply-patch' $patch`, true},
		{"patch run by codex with a caret in its name", `$patch = "` + envelope + `"; & cmd.exe /c 'c^odex.exe --codex-run-as-apply-patch' $patch`, true},
		{"patch run by codex behind Start-Process cmd", `$patch = "` + envelope + `"; Start-Process cmd -ArgumentList '/c', 'C:\dc\codex.exe --codex-run-as-apply-patch', $patch`, true},
		{"patch run by codex behind Start-Process -FilePath", `$patch = "` + envelope + `"; Start-Process -FilePath 'C:\dc\codex.exe' -ArgumentList '--codex-run-as-apply-patch', $patch`, true},
		{"cmd echoes a quoted codex name and the flag", `$patch = "` + envelope + `"; & cmd.exe /c echo 'C:\dc\codex.exe' --codex-run-as-apply-patch $patch`, false},
		{"cmd echoes one quoted codex command line", `$patch = "` + envelope + `"; & cmd.exe /c 'echo C:\dc\codex.exe --codex-run-as-apply-patch' $patch`, false},
		{"Start-Process of an unrelated program lists codex and the flag", `$patch = "` + envelope + `"; Start-Process whoami.exe -ArgumentList 'C:\dc\codex.exe', '--codex-run-as-apply-patch', $patch`, false},
		{"patch run by codex behind Start-Process", `$patch = "` + envelope + `"; Start-Process 'C:\dc\codex.exe' -ArgumentList '--codex-run-as-apply-patch', $patch`, true},
		{"eight alternatives, state last", alternatives(7, state, -1, ""), true},
		{"nine alternatives, state last", alternatives(8, state, -1, ""), true},
		{"twelve alternatives, state last", alternatives(11, state, -1, ""), true},
		{"eight ordinary alternatives", alternatives(7, ordinaryLast, -1, ""), false},
		{"thirty alternatives, state last", alternatives(30, state, -1, ""), true},
		{"state is the ninth branch of eleven", alternatives(10, ordinaryLast, 8, ""), true},
		{"nine alternatives, state last, read elsewhere", alternatives(8, state, -1, readState), true},
		{"nine ordinary alternatives", alternatives(8, ordinaryLast, -1, ""), false},
		{"nine ordinary alternatives, state read elsewhere", alternatives(8, ordinaryLast, -1, readState), false},
		{"nine ordinary alternatives, state bound and unused", alternatives(8, ordinaryLast, -1, unusedBinding), false},
		{"nine ordinary alternatives, state as written text", alternatives(8, ordinaryLast, -1, stateAsContent), false},
		{"twenty ordinary alternatives, state read elsewhere", alternatives(19, ordinaryLast, -1, readState), false},
		{"ninth protected path only read", chain("p", 8, state, -1, `[IO.File]::ReadAllText($p)`), false},
		{"ninth protected path read by Get-Content", chain("p", 8, state, -1, `Get-Content $p`), false},
		{"ninth protected path never used", chain("p", 8, state, -1, `Write-Output done`), false},
		{"ninth protected path rebound before an ordinary write", chain("p", 8, state, -1, `$p = '`+project+`'; [IO.File]::WriteAllText($p, 'x')`), false},
		{"ninth protected path written", chain("p", 8, state, -1, `[IO.File]::WriteAllText($p, 'x')`), true},
		{"protected path built from a ninth directory", chain("d", 8, `C:\Users\Alice\.defenseclaw\..`, -1, `$p = "$d\.defenseclaw\config.yaml"; [IO.File]::WriteAllText($p, 'x')`), true},
		{"ordinary path built from nine directories", chain("d", 8, `C:\Users\Alice\project\defenseclaw_last`, -1, `$p = "$d\notes.txt"; [IO.File]::WriteAllText($p, 'x')`), false},
		{"sixty ordinary alternatives", alternatives(59, ordinaryLast, -1, ""), false},
		{"seventy alternatives, state last", alternatives(69, state, -1, ""), true},
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
