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
		{"sixty-five alternatives, state last, only read", chain("p", 64, state, -1, `[IO.File]::ReadAllText($p)`), false},
		{"sixty-five ordinary alternatives, ordinary write", chain("p", 64, ordinaryLast, -1, `[IO.File]::WriteAllText($p, 'x')`), false},
		{"sixty-five ordinary alternatives, state read separately, ordinary write", chain("p", 64, ordinaryLast, -1, `[IO.File]::ReadAllText('`+state+`'); [IO.File]::WriteAllText($p, 'x')`), false},
		{"ninety ordinary alternatives", chain("p", 89, ordinaryLast, -1, `[IO.File]::WriteAllText($p, 'x')`), false},
		{"ninety alternatives, state last, only read", chain("p", 89, state, -1, `[IO.File]::ReadAllText($p)`), false},
		{"ninety alternatives, state last, written", chain("p", 89, state, -1, `[IO.File]::WriteAllText($p, 'x')`), true},
		{"ninety alternatives, state is the fiftieth, written", chain("p", 89, ordinaryLast, 49, `[IO.File]::WriteAllText($p, 'x')`), true},
		{"sixty-five ordinary directories, a child written", chain("d", 64, `C:\Users\Alice\project\defenseclaw_last`, -1, `$p = "$d\notes.txt"; [IO.File]::WriteAllText($p, 'x')`), false},
		{"sixty-five directories, a walk up from each stays outside the state directory", chain("d", 64, `C:\Users\Alice\project\defenseclaw_last`, -1, `$p = "$d\..\.defenseclaw\config.yaml"; [IO.File]::WriteAllText($p, 'x')`), false},
		{"sixty-five directories, a walk up from one shallower directory reaches the state directory", chain("d", 64, `C:\Users\Alice\defenseclaw_last`, -1, `$p = "$d\..\.defenseclaw\config.yaml"; [IO.File]::WriteAllText($p, 'x')`), true},
		{"values carried around a loop", `$a = '` + state + `'; $b = '` + project + `defenseclaw1'; $c = '` + project + `defenseclaw2'; $d = '` + project + `defenseclaw3'; foreach ($i in 1..4) { [IO.File]::WriteAllText($d, 'x'); $d = $c; $c = $b; $b = $a }`, true},
		{"cmd start /machine option then codex", `$patch = "` + envelope + `"; & cmd.exe /c 'start /machine amd64 C:\dc\codex.exe --codex-run-as-apply-patch' $patch`, true},
		{"cmd start /machine option then another program", `$patch = "` + envelope + `"; & cmd.exe /c 'start /machine amd64 whoami.exe C:\dc\codex.exe --codex-run-as-apply-patch' $patch`, false},
		{"cmd if with a false literal comparison never runs codex", `$patch = "` + envelope + `"; & cmd.exe /c 'if 1==2 C:\dc\codex.exe --codex-run-as-apply-patch' $patch`, false},
		{"cmd if not with a true literal comparison never runs codex", `$patch = "` + envelope + `"; & cmd.exe /c 'if not 1==1 C:\dc\codex.exe --codex-run-as-apply-patch' $patch`, false},
		{"cmd if with a false comparison never starts codex", `$patch = "` + envelope + `"; & cmd.exe /c 'if 1==2 start /b C:\dc\codex.exe --codex-run-as-apply-patch' $patch`, false},
		{"cmd if with a false numeric operator never runs codex", `$patch = "` + envelope + `"; & cmd.exe /c 'if 1 GTR 2 C:\dc\codex.exe --codex-run-as-apply-patch' $patch`, false},
		{"cmd if with a true numeric operator runs codex", `$patch = "` + envelope + `"; & cmd.exe /c 'if 2 GTR 1 C:\dc\codex.exe --codex-run-as-apply-patch' $patch`, true},
		{"cmd if compares case-sensitively without /i", `$patch = "` + envelope + `"; & cmd.exe /c 'if A==a C:\dc\codex.exe --codex-run-as-apply-patch' $patch`, false},
		{"cmd if compares without case with /i", `$patch = "` + envelope + `"; & cmd.exe /c 'if /i A==a C:\dc\codex.exe --codex-run-as-apply-patch' $patch`, true},
		{"cmd if not with a false comparison runs codex", `$patch = "` + envelope + `"; & cmd.exe /c 'if not 1==2 C:\dc\codex.exe --codex-run-as-apply-patch' $patch`, true},
		{"cmd if on a variable runs codex when cmd decides", `$patch = "` + envelope + `"; & cmd.exe /c 'if %X%==1 C:\dc\codex.exe --codex-run-as-apply-patch' $patch`, true},
		{"cmd if true, codex only in the else", `$patch = "` + envelope + `"; & cmd.exe /c 'if 1==1 (whoami.exe) else (C:\dc\codex.exe --codex-run-as-apply-patch)' $patch`, false},
		{"cmd if false, codex in the else", `$patch = "` + envelope + `"; & cmd.exe /c 'if 1==2 (whoami.exe) else (C:\dc\codex.exe --codex-run-as-apply-patch)' $patch`, true},
		{"cmd if true, codex in the then group", `$patch = "` + envelope + `"; & cmd.exe /c 'if 1==1 (C:\dc\codex.exe --codex-run-as-apply-patch) else (whoami.exe)' $patch`, true},
		{"cmd if false, codex in the then group", `$patch = "` + envelope + `"; & cmd.exe /c 'if 1==2 (C:\dc\codex.exe --codex-run-as-apply-patch) else (whoami.exe)' $patch`, false},
		{"cmd if true with an unparenthesised else", `$patch = "` + envelope + `"; & cmd.exe /c 'if 1==1 (whoami.exe) else C:\dc\codex.exe --codex-run-as-apply-patch' $patch`, false},
		{"cmd if false, codex later on the same line", `$patch = "` + envelope + `"; & cmd.exe /c 'if 1==2 echo hi & C:\dc\codex.exe --codex-run-as-apply-patch' $patch`, false},
		{"cmd if true, codex later on the same line", `$patch = "` + envelope + `"; & cmd.exe /c 'if 1==1 echo hi & C:\dc\codex.exe --codex-run-as-apply-patch' $patch`, true},
		{"cmd codex after a closed false if", `$patch = "` + envelope + `"; & cmd.exe /c '(if 1==2 echo hi) & C:\dc\codex.exe --codex-run-as-apply-patch' $patch`, true},
		{"cmd nested if false inside a true if", `$patch = "` + envelope + `"; & cmd.exe /c 'if 1==1 (if 1==2 C:\dc\codex.exe --codex-run-as-apply-patch)' $patch`, false},
		{"cmd for loop over a false if", `$patch = "` + envelope + `"; & cmd.exe /c 'for %i in (1) do if 1==2 C:\dc\codex.exe --codex-run-as-apply-patch' $patch`, false},
		{"cmd for loop over a true if", `$patch = "` + envelope + `"; & cmd.exe /c 'for %i in (1) do if 1==1 C:\dc\codex.exe --codex-run-as-apply-patch' $patch`, true},
		{"codex receives a different long option", `$patch = "` + envelope + `"; & 'C:\dc\codex.exe' --codex-run-as-apply-patch-help $patch`, false},
		{"cmd codex receives a different long option", `$patch = "` + envelope + `"; & cmd.exe /c 'C:\dc\codex.exe --codex-run-as-apply-patch-help' $patch`, false},
		{"codex receives the option in a list", `$patch = "` + envelope + `"; & cmd.exe /c 'C:\dc\codex.exe -x,--codex-run-as-apply-patch' $patch`, true},
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

// TestPowerShellPlainPathSignature: values share a signature only when the
// proof cannot read them differently at any use, in any path built from them.
func TestPowerShellPlainPathSignature(t *testing.T) {
	const home = `C:\Users\Alice`
	plain := newPSMerger(home, home+`\project`, nil)
	merger := newPSMerger(home, home+`\project`, map[string]string{
		`C:/Users/Alice/project/defenseclaw_link.txt`: `C:/Users/Alice/.defenseclaw/config.yaml`,
		"\x00dir:C:/Users/Alice/project/jl":           `C:/Users/Alice/.defenseclaw`,
		`C:/Users/Alice/project/ordinary.txt`:         `C:/Users/Alice/project/ordinary.txt`,
	})
	same := [][2]string{
		{`C:\Users\Alice\project\defenseclaw_a`, `c:/users/alice/project/defenseclaw_b.txt`},
		{`C:\Users\Alice\a\b\defenseclaw one`, `C:\Users\Alice\other\c\defenseclaw-two(1)`},
		{`C:\Users\Bob\a\defenseclaw_a`, `C:\Users\Carol\b\defenseclaw_b`},
		{`D:\work\defenseclaw_a`, `E:\other\defenseclaw_b`},
		// A relative path is the absolute path under the working directory.
		{`.\defenseclaw_a`, `C:\Users\Alice\project\defenseclaw_b`},
		{`defenseclaw_a\b`, `.\.\sub\defenseclaw_b`},
		// A dotted name that goes on past the state directory name is another name.
		{`C:\Users\Alice\project\.defenseclaw_a`, `C:\Users\Alice\project\defenseclaw_b`},
		{`C:\Users\Alice\.defenseclaw_a`, `C:\Users\Alice\defenseclaw_b`},
		{`C:\Users\Alice\project\a.defenseclaw`, `C:\Users\Alice\project\defenseclaw_b`},
		// Below a remote share only the depth matters.
		{`\\srv\share\defenseclaw_a`, `\\other\data\defenseclaw_b`},
		{`//srv/share/a/defenseclaw_a`, `\\other\data\b\defenseclaw_b`},
		{`C:\Users\Alice\project\ordinary.txt`, `C:\Users\Alice\project\defenseclaw_b`},
	}
	for _, pair := range same {
		a, okA := plain.signature(pair[0])
		b, okB := plain.signature(pair[1])
		if !okA || !okB || a != b {
			t.Errorf("%q and %q: signatures %q (%t) and %q (%t), want the same", pair[0], pair[1], a, okA, b, okB)
		}
	}
	different := [][2]string{
		{`C:\Users\Alice\project\defenseclaw_a`, `C:\Users\Alice\defenseclaw_a`},
		{`C:\Users\Alice\project\defenseclaw_a`, `C:\Users\Bob\project\defenseclaw_a`},
		{`C:\Users\Alice\project\defenseclaw_a`, `C:\Users\Alice\project\defenseclaw_a\`},
		{`C:\Users\Alice\project\defenseclaw_a`, `D:\Users\Alice\project\defenseclaw_a`},
		{`C:\Users\Alice`, `C:\Users\Alice\project`},
		{`.\defenseclaw_a`, `defenseclaw_a\b`},
		{`\\srv\share\defenseclaw_a`, `\\srv\share\a\defenseclaw_a`},
		{`\\srv\share\defenseclaw_a`, `C:\Users\Alice\project\defenseclaw_a`},
	}
	for _, pair := range different {
		a, okA := plain.signature(pair[0])
		b, okB := plain.signature(pair[1])
		if !okA || !okB || a == b {
			t.Errorf("%q and %q: signatures %q (%t) and %q (%t), want different", pair[0], pair[1], a, okA, b, okB)
		}
	}
	// A name that only starts with a known link's text is another name.
	siblingA, okA := merger.signature(`C:\Users\Alice\project\defenseclaw_link.txt0.txt`)
	siblingB, okB := merger.signature(`.\defenseclaw_link.txtother`)
	if !okA || !okB || siblingA != siblingB {
		t.Errorf("siblings of a known link: signatures %q (%t) and %q (%t), want the same", siblingA, okA, siblingB, okB)
	}
	for _, value := range []string{
		`C:\Users\Alice\.defenseclaw\config.yaml`, `C:\Users\Alice\project\.DefenseClaw`, `C:\Users\Alice\.de`, `C:\Users\Alice\.`,
		`C:\Users\Alice\project\..\x`, `C:\Users\Alice\project\.\x`, `\rooted\defenseclaw`, `..\defenseclaw`, `.\sub\..\defenseclaw`, `.`, `.\`,
		`C:\Users\Alice\defenseclaw~1`, `C:\Users\Alice\defenseclaw$x`, `C:\Users\Alice\defenseclaw.`, `C:\Users\Alice\defenseclaw `,
		`C:\Users\Alice\defenseclaw:stream`, `C:\Users\Alice\project*\defenseclaw`, `C:\Users\Alice\\defenseclaw`, `C:\Users\Alice\defenseclaw%x%`,
		`C:\Users\Alice\défenseclaw`, `C:defenseclaw`, "",
		// A link or hard link the hook client resolved, however it is spelled.
		`C:\Users\Alice\project\defenseclaw_link.txt`, `c:/users/alice/project/DEFENSECLAW_LINK.TXT`, `.\defenseclaw_link.txt`, `defenseclaw_link.txt`,
		`C:\Users\Alice\project\defenseclaw_link.txt\child`, `C:\Users\Alice\project\defenseclaw_link.txt.`, `C:\Users\Alice\project\defenseclaw_link.txt:s`,
		`C:\Users\Alice\project\jl`, `.\jl\`, `C:\Users\Alice\project\jl\x.txt`,
		// A directory that holds a link, or a name cut short before one.
		`C:\Users\Alice\project`, `C:\Users\Alice`, `.\`, `C:\Users\Alice\project\defenseclaw_li`, `.\defenseclaw_l`,
		// A local server, an administrative share, a device path, a bare share.
		`\\localhost\c$\Users\Alice\defenseclaw`, `\\127.0.0.1\share\defenseclaw`, `\\srv\c$\defenseclaw`, `\\srv\share`, `\\srv\share\`,
		`\\?\C:\Users\Alice\defenseclaw`, `\\.\C:\defenseclaw`, `\\srv\share\.defenseclaw`, `\\srv\share\..\defenseclaw`, `\\srv\share\a:b`,
	} {
		if signature, ok := merger.signature(value); ok {
			t.Errorf("%q has signature %q, want none", value, signature)
		}
	}
}

// TestPowerShellBoundValueMergeKeepsLinksAndReadsEveryOrdinaryFamily: a
// variable bound to more ordinary files than the proof holds apart must not
// block a command that does not touch state, whatever the spelling of the
// files (relative, remote share, dotted name, forward slashes); a link onto
// state stays a protected value wherever it is among them.
func TestPowerShellBoundValueMergeKeepsLinksAndReadsEveryOrdinaryFamily(t *testing.T) {
	const connectorName = "ps-bound-merge"
	installToolCallCorpusProfileConnector(t, connectorName, "default")
	const home = `C:\Users\Alice`
	const state = `C:\Users\Alice\.defenseclaw\config.yaml`
	const link = `C:\Users\Alice\project\defenseclaw_link.txt`
	const envelope = "*** Begin Patch`n*** Update File: C:/Users/Alice/.defenseclaw/config.yaml`n@@`n-a`n+b`n*** End Patch"
	resolved := map[string]string{
		"C:/Users/Alice/.defenseclaw":             "C:/Users/Alice/.defenseclaw",
		"C:/Users/Alice/.defenseclaw/config.yaml": "C:/Users/Alice/.defenseclaw/config.yaml",
	}
	linked := map[string]string{}
	for key, value := range resolved {
		linked[key] = value
	}
	for _, spelling := range []string{link, strings.ReplaceAll(link, `\`, "/")} {
		linked[spelling] = "C:/Users/Alice/.defenseclaw/config.yaml"
	}
	linked[`C:/Users/Alice/project/defenseclaw_dir/link.txt`] = "C:/Users/Alice/.defenseclaw/config.yaml"
	// The client resolves a path under the link and a stream of it to the state too.
	for _, suffix := range []string{`/child.txt`, `:s`} {
		linked[strings.ReplaceAll(link, `\`, "/")+suffix] = "C:/Users/Alice/.defenseclaw/config.yaml"
	}
	// binding binds $p to n files (the tail reads the state too: a command that
	// never names state has no link to follow) named prefix<i>.txt, then to last, in the
	// branches of an if chain, then runs tail.
	binding := func(prefix string, n int, last, tail string) string {
		var branches strings.Builder
		for i := 0; i < n; i++ {
			keyword := "if"
			if i > 0 {
				keyword = " elseif"
			}
			fmt.Fprintf(&branches, `%s ($c%d) { $p = '%s%d.txt' }`, keyword, i, prefix, i)
		}
		return `$p = '` + prefix + `base.txt'; ` + branches.String() + ` else { $p = '` + last + `' }; ` + tail
	}
	readThenWrite := `[IO.File]::ReadAllText('` + state + `'); [IO.File]::WriteAllText($p, 'x')`
	write := `[IO.File]::WriteAllText($p, 'x')`
	families := []struct{ name, prefix, ordinary string }{
		{"drive path", `C:\Users\Alice\project\defenseclaw_note`, `C:\Users\Alice\project\defenseclaw_last.txt`},
		{"forward-slash drive path", `C:/Users/Alice/project/defenseclaw_note`, `C:/Users/Alice/project/defenseclaw_last.txt`},
		{"relative path", `.\defenseclaw_note`, `.\defenseclaw_last.txt`},
		{"bare relative path", `sub\defenseclaw_note`, `sub\defenseclaw_last.txt`},
		{"remote share", `\\server\share\project\defenseclaw_note`, `\\server\share\project\defenseclaw_last.txt`},
		{"dotted name under the project", `C:\Users\Alice\project\.defenseclaw_note`, `C:\Users\Alice\project\.defenseclaw_last.txt`},
		{"dotted name under the home", `C:\Users\Alice\.defenseclaw_note`, `C:\Users\Alice\.defenseclaw_last.txt`},
		{"relative dotted name", `.\.defenseclaw_note`, `.\.defenseclaw_last.txt`},
	}
	type row struct {
		name, command string
		block, links  bool
	}
	var rows []row
	for _, family := range families {
		for _, n := range []int{9, 65, 90} {
			rows = append(rows,
				row{name: fmt.Sprintf("%s, %d ordinary, a separate state read, an ordinary write", family.name, n), command: binding(family.prefix, n, family.ordinary, readThenWrite)},
				row{name: fmt.Sprintf("%s, %d ordinary, the state read only", family.name, n), command: binding(family.prefix, n, family.ordinary, `[IO.File]::ReadAllText('`+state+`')`)},
				row{name: fmt.Sprintf("%s, %d ordinary, a link in the map but unused", family.name, n), command: binding(family.prefix, n, family.ordinary, readThenWrite), links: true},
				row{name: fmt.Sprintf("%s, %d ordinary, the state last, written", family.name, n), command: binding(family.prefix, n, state, write), block: true},
				row{name: fmt.Sprintf("%s, %d ordinary, the state last, only read", family.name, n), command: binding(family.prefix, n, state, `[IO.File]::ReadAllText($p)`)},
			)
		}
	}
	for _, n := range []int{0, 7, 8, 9, 40, 70} {
		rows = append(rows,
			row{name: fmt.Sprintf("a known link last among %d, written", n), command: binding(`C:\Users\Alice\project\defenseclaw_note`, n, link, readThenWrite), block: true, links: true},
			row{name: fmt.Sprintf("a known link last among %d, only read", n), command: binding(`C:\Users\Alice\project\defenseclaw_note`, n, link, `[IO.File]::ReadAllText($p)`), links: true},
			row{name: fmt.Sprintf("a known link spelled with slashes last among %d, written", n), command: binding(`C:\Users\Alice\project\defenseclaw_note`, n, strings.ReplaceAll(link, `\`, "/"), readThenWrite), block: true, links: true},
			row{name: fmt.Sprintf("a known link spelled relative last among %d, written", n), command: binding(`.\defenseclaw_note`, n, `.\defenseclaw_link.txt`, readThenWrite), block: true, links: true},
			row{name: fmt.Sprintf("a known link last among %d relative files, written", n), command: binding(`defenseclaw_note`, n, link, readThenWrite), block: true, links: true},
			row{name: fmt.Sprintf("the same files with no link in the map, %d, written", n), command: binding(`C:\Users\Alice\project\defenseclaw_note`, n, link, readThenWrite)},
		)
	}
	// A directory that holds a link, or a name cut short before one, is read
	// against the known link, not merged with the other directories.
	holder := `[IO.File]::ReadAllText('` + state + `'); $q = "$p\link.txt"; [IO.File]::WriteAllText($q, 'x')`
	cutShort := `[IO.File]::ReadAllText('` + state + `'); $q = "${p}nk.txt"; [IO.File]::WriteAllText($q, 'x')`
	for _, n := range []int{3, 12, 70} {
		rows = append(rows,
			row{name: fmt.Sprintf("the directory that holds a known link among %d directories", n), command: binding(`C:\Users\Alice\project\defenseclaw_other`, n, `C:\Users\Alice\project\defenseclaw_dir`, holder), block: true, links: true},
			row{name: fmt.Sprintf("the same directories with no link in the map, %d", n), command: binding(`C:\Users\Alice\project\defenseclaw_other`, n, `C:\Users\Alice\project\defenseclaw_dir`, holder)},
			row{name: fmt.Sprintf("a directory that does not hold the link among %d", n), command: binding(`C:\Users\Alice\project\defenseclaw_other`, n, `C:\Users\Alice\project\defenseclaw_sub`, holder), links: true},
			row{name: fmt.Sprintf("a name cut short before a known link among %d", n), command: binding(`C:\Users\Alice\project\defenseclaw_note`, n, `C:\Users\Alice\project\defenseclaw_li`, cutShort), block: true, links: true},
			row{name: fmt.Sprintf("a name cut short before another name among %d", n), command: binding(`C:\Users\Alice\project\defenseclaw_note`, n, `C:\Users\Alice\project\defenseclaw_lx`, cutShort), links: true},
		)
	}
	// A name that only starts with the known link's text and goes on in the same
	// segment is another file, not the link and not a path under it; a path under
	// the link and a stream of it are still the link.
	const linkName = `C:\Users\Alice\project\defenseclaw_link.txt`
	linkRead := `[IO.File]::ReadAllText('` + state + `'); [IO.File]::ReadAllText('` + linkName + `'); [IO.File]::WriteAllText($p, 'x')`
	for _, n := range []int{3, 9, 40, 65, 90} {
		rows = append(rows,
			row{name: fmt.Sprintf("%d siblings that start with the known link's text, a state read, an ordinary write", n), command: binding(linkName, n, linkName+`last.txt`, readThenWrite), links: true},
			row{name: fmt.Sprintf("%d siblings that start with the known link's text, a link read, an ordinary write", n), command: binding(linkName, n, linkName+`last.txt`, linkRead), links: true},
			row{name: fmt.Sprintf("%d relative siblings that start with the known link's text", n), command: binding(`.\defenseclaw_link.txt`, n, `.\defenseclaw_link.txtlast.txt`, linkRead), links: true},
			row{name: fmt.Sprintf("%d siblings of the known link, then the link itself", n), command: binding(linkName, n, linkName, readThenWrite), block: true, links: true},
			row{name: fmt.Sprintf("%d siblings of the known link, then a path under it", n), command: binding(linkName, n, linkName+`\child.txt`, readThenWrite), block: true, links: true},
			row{name: fmt.Sprintf("%d siblings of the known link, then a stream of it", n), command: binding(linkName, n, linkName+`:s`, readThenWrite), block: true, links: true},
			row{name: fmt.Sprintf("%d siblings of the known link with no link in the map", n), command: binding(linkName, n, linkName+`last.txt`, linkRead)},
		)
	}
	rows = append(rows, row{name: "ninety ordinary files with plain punctuation in their names", command: binding(`C:\Users\Alice\project\defenseclaw+note #@,=`, 90, `C:\Users\Alice\project\defenseclaw+last`, readThenWrite)})
	patch := `$patch = "` + envelope + `"; & cmd.exe /c `
	for _, tc := range []struct {
		name, condition string
		block           bool
	}{
		{"a leading zero is not octal, 09 is above 8", `09 GTR 8`, true},
		{"09 is not below 8", `09 LSS 8`, false},
		{"010 is above 9", `010 GTR 9`, true},
		{"010 is not below 9", `010 LSS 9`, false},
		{"010 equals 10", `010 EQU 10`, true},
		{"010 does not equal 8", `010 EQU 8`, false},
		{"010 differs from 8", `010 NEQ 8`, true},
		{"zeros equal zero", `000 EQU 0`, true},
		{"a negative number is below zero", `-1 LSS 0`, true},
		{"a negative number is not above zero", `-1 GTR 0`, false},
		{"a negative number is below a longer positive one", `-100 LSS 5`, true},
		{"two negative numbers", `-100 LSS -5`, true},
		{"a number past 64 bits is above a small one", `99999999999999999999 GTR 9`, true},
		{"a number past 64 bits is not below a small one", `99999999999999999999 LSS 9`, false},
		{"decimal control", `10 GTR 9`, true},
		{"decimal control, false", `10 LSS 9`, false},
		{"text is compared as text", `abc GTR abd`, false},
		{"text is compared as text, true", `abd GTR abc`, true},
		{"a number against text is text", `10 LSS 9a`, true},
		{"a hexadecimal operand next to a number is not decided", `0x10 EQU 16`, true},
		{"a hexadecimal operand next to a number is not decided, false twin", `0x10 EQU 17`, true},
	} {
		rows = append(rows, row{name: "cmd if " + tc.name, command: patch + `'if ` + tc.condition + ` C:\dc\codex.exe --codex-run-as-apply-patch' $patch`, block: tc.block})
	}
	rows = append(rows,
		row{name: "an upper-case Codex option is not the patch option", command: `$patch = "` + envelope + `"; & 'C:\dc\codex.exe' --CODEX-RUN-AS-APPLY-PATCH $patch`},
		row{name: "a mixed-case Codex option is not the patch option", command: `$patch = "` + envelope + `"; & 'C:\dc\codex.exe' --Codex-Run-As-Apply-Patch $patch`},
		row{name: "an upper-case Codex option behind cmd", command: patch + `'C:\dc\codex.exe --CODEX-RUN-AS-APPLY-PATCH' $patch`},
		row{name: "the exact Codex option", command: `$patch = "` + envelope + `"; & 'C:\dc\codex.exe' --codex-run-as-apply-patch $patch`, block: true},
		row{name: "the exact Codex option behind cmd", command: patch + `'C:\dc\codex.exe --codex-run-as-apply-patch' $patch`, block: true},
	)
	api := &APIServer{}
	for _, tc := range rows {
		for _, managed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/managed=%t", tc.name, managed), func(t *testing.T) {
				args, _ := json.Marshal(map[string]string{"command": tc.command})
				input := actionfacts.Input{Tool: "shell_command", Args: args, CWD: home + `\project`, ActiveHome: home}
				input.DialectHint = agentHookWindowsShellDialect(input)
				targets := resolved
				if tc.links {
					targets = linked
				}
				findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
					Input: input, LegacyText: string(args), Connector: connectorName,
					EnforcementCapable: true, ResolvedWriteTargets: targets, ProtectedHomeHook: managed,
				})
				verdict := buildVerdict(findings, "tool_call")
				if got := verdict.Action == "block" && api.provenActiveStateMutation(t.Context(), verdict); got != tc.block {
					t.Fatalf("observe-mode hard block=%t, want %t (action %q, findings %v)", got, tc.block, verdict.Action, findingIDs(findings))
				}
			})
		}
	}
}
