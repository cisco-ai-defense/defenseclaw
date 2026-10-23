// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"slices"
	"testing"
)

// An exported function or a PowerShell scriptblock literal is a definition
// or a value. Only a command that can run it exposes its body.
func TestSimpleCommandsInertDefinitionsRunNothing(t *testing.T) {
	const destructivePOSIX, destructivePS = "rm -rf /", `Remove-Item -Recurse -Force C:\`
	for _, tt := range []struct {
		name, command string
		dialect       Dialect
		want          string
		ran           bool
	}{
		{"export only", "f() { rm -rf /; }; export -f f", DialectPOSIX, destructivePOSIX, false},
		{"export then builtin", "f() { rm -rf /; }; export -f f; echo done", DialectPOSIX, destructivePOSIX, false},
		{"declare export then utility", "f() { rm -rf /; }; declare -fx f; ls -la", DialectPOSIX, destructivePOSIX, false},
		{"typeset export in list", "f() { rm -rf /; }; typeset -fx f && printf ok", DialectPOSIX, destructivePOSIX, false},
		{"child shell before export", "f() { rm -rf /; }; bash -c f; export -f f", DialectPOSIX, destructivePOSIX, false},
		{"export inside called function", "f() { rm -rf /; }; g() { export -f f; }; g; echo done", DialectPOSIX, destructivePOSIX, false},
		{"child shell", "f() { rm -rf /; }; export -f f; bash -c f", DialectPOSIX, destructivePOSIX, true},
		{"child shell through env", "f() { rm -rf /; }; export -f f; env bash -c f", DialectPOSIX, destructivePOSIX, true},
		{"child shell through xargs", "f() { rm -rf /; }; export -f f; printf x | xargs bash -c f", DialectPOSIX, destructivePOSIX, true},
		{"child shell through find", `f() { rm -rf /; }; export -f f; find . -exec sh -c f \;`, DialectPOSIX, destructivePOSIX, true},
		{"child shell by full path", "f() { rm -rf /; }; declare -fx f; /bin/bash -c f", DialectPOSIX, destructivePOSIX, true},
		{"relative script", "f() { rm -rf /; }; export -f f; ./run.sh", DialectPOSIX, destructivePOSIX, true},
		{"script outside system directories", "f() { rm -rf /; }; export -f f; /opt/tools/run", DialectPOSIX, destructivePOSIX, true},
		{"wrapped script", "f() { rm -rf /; }; export -f f; nohup ./run", DialectPOSIX, destructivePOSIX, true},
		{"interpreter names function", `f() { rm -rf /; }; export -f f; python3 -c "import os; os.system('f')"`, DialectPOSIX, destructivePOSIX, true},
		{"child shell in substitution", "f() { rm -rf /; }; export -f f; x=$(bash -c f)", DialectPOSIX, destructivePOSIX, true},
		{"child shell in called function", "f() { rm -rf /; }; g() { bash -c f; }; export -f f; g", DialectPOSIX, destructivePOSIX, true},
		{"export inside called function then child", "f() { rm -rf /; }; g() { export -f f; }; g; bash -c f", DialectPOSIX, destructivePOSIX, true},
		{"redefined after export", "f() { echo ok; }; export -f f; f() { rm -rf /; }; bash -c f", DialectPOSIX, destructivePOSIX, true},
		{"bare scriptblock", `{ Remove-Item -Recurse -Force C:\ }`, DialectPowerShell, destructivePS, false},
		{"bare scriptblock after statement", `Write-Output a; { Remove-Item -Recurse -Force C:\ }`, DialectPowerShell, destructivePS, false},
		{"bare scriptblock before statement", `{ Remove-Item -Recurse -Force C:\ }; Write-Output a`, DialectPowerShell, destructivePS, false},
		{"multiline bare scriptblock", "{\n  Remove-Item -Recurse -Force C:\\\n}\nWrite-Output a", DialectPowerShell, destructivePS, false},
		{"bare scriptblock in if body", `if ($true) { { Remove-Item -Recurse -Force C:\ } }`, DialectPowerShell, destructivePS, false},
		{"bare scriptblock in invoked block", `& { { Remove-Item -Recurse -Force C:\ } }`, DialectPowerShell, destructivePS, false},
		{"bare scriptblock with quoted brace", `{ Write-Output '}'; Remove-Item -Recurse -Force C:\ }; Write-Output a`, DialectPowerShell, destructivePS, false},
		{"invoked scriptblock", `& { Remove-Item -Recurse -Force C:\ }`, DialectPowerShell, destructivePS, true},
		{"dot-sourced scriptblock", `. { Remove-Item -Recurse -Force C:\ }`, DialectPowerShell, destructivePS, true},
		{"scriptblock piped to a consumer", `{ Remove-Item -Recurse -Force C:\ } | ForEach-Object Invoke`, DialectPowerShell, destructivePS, true},
		{"if body", `if ($true) { Remove-Item -Recurse -Force C:\ }`, DialectPowerShell, destructivePS, true},
		// Loop round 3: an exported name is data outside shell text; a child
		// shell exposes the bodies only when it can call one.
		{"exported name as data", "f() { rm -rf /; }; export -f f; ls f", DialectPOSIX, destructivePOSIX, false},
		{"exported name after options", "f() { rm -rf /; }; export -f f; cat -- f", DialectPOSIX, destructivePOSIX, false},
		{"exported name run by an exec wrapper", "f() { rm -rf /; }; export -f f; env f", DialectPOSIX, destructivePOSIX, false},
		{"shell name as data", "f() { rm -rf /; }; export -f f; grep bash /etc/shells", DialectPOSIX, destructivePOSIX, false},
		{"child shell calls nothing", "f() { rm -rf /; }; export -f f; bash -c 'echo ok'", DialectPOSIX, destructivePOSIX, false},
		{"wrapped child shell calls nothing", "f() { rm -rf /; }; export -f f; env bash -c 'echo ok'", DialectPOSIX, destructivePOSIX, false},
		{"runner child shell calls nothing", "f() { rm -rf /; }; export -f f; printf x | xargs bash -c 'echo ok'", DialectPOSIX, destructivePOSIX, false},
		{"find child shell calls nothing", `f() { rm -rf /; }; export -f f; find . -exec sh -c 'echo {}' \;`, DialectPOSIX, destructivePOSIX, false},
		{"child shell skips function lookup", "f() { rm -rf /; }; export -f f; bash -c 'command f'", DialectPOSIX, destructivePOSIX, false},
		{"command -v of an exported name", "f() { rm -rf /; }; export -f f; command -v f", DialectPOSIX, destructivePOSIX, false},
		{"child shell calls among others", "f() { rm -rf /; }; export -f f; bash -c 'echo ok; f'", DialectPOSIX, destructivePOSIX, true},
		{"nested child shell", `f() { rm -rf /; }; export -f f; bash -c "bash -c f"`, DialectPOSIX, destructivePOSIX, true},
		{"child shell eval", "f() { rm -rf /; }; export -f f; bash -c 'eval f'", DialectPOSIX, destructivePOSIX, true},
		{"child shell command eval", "f() { rm -rf /; }; export -f f; sh -c 'command eval f'", DialectPOSIX, destructivePOSIX, true},
		{"child shell sources a file", "f() { rm -rf /; }; export -f f; bash -c . ./env", DialectPOSIX, destructivePOSIX, true},
		{"sourced file", "f() { rm -rf /; }; export -f f; source ./env", DialectPOSIX, destructivePOSIX, true},
		{"runner input placeholder", "f() { rm -rf /; }; export -f f; printf f | xargs -I{} sh -c {}", DialectPOSIX, destructivePOSIX, true},
		{"runner runtime text", `f() { rm -rf /; }; export -f f; watch "$cmd"`, DialectPOSIX, destructivePOSIX, true},
		{"shell reads a script file", "f() { rm -rf /; }; export -f f; bash setup", DialectPOSIX, destructivePOSIX, true},
		{"runner hands the name to a shell", "f() { rm -rf /; }; export -f f; watch f", DialectPOSIX, destructivePOSIX, true},
		{"command text in an argument", "f() { rm -rf /; }; export -f f; tmux new-session 'bash -c f'", DialectPOSIX, destructivePOSIX, true},
		// Loop round 3: command and builtin skip function lookup.
		{"command skips the function", "f() { rm -rf /; }; command f", DialectPOSIX, destructivePOSIX, false},
		{"command -p skips the function", "f() { rm -rf /; }; command -p f", DialectPOSIX, destructivePOSIX, false},
		{"command -v only describes", "f() { rm -rf /; }; command -v f", DialectPOSIX, destructivePOSIX, false},
		{"builtin runs only builtins", "f() { rm -rf /; }; builtin f", DialectPOSIX, destructivePOSIX, false},
		{"builtin command", "f() { rm -rf /; }; builtin command f", DialectPOSIX, destructivePOSIX, false},
		{"eval of command", "f() { rm -rf /; }; eval 'command f'", DialectPOSIX, destructivePOSIX, false},
		{"command eval", "f() { rm -rf /; }; command eval f", DialectPOSIX, destructivePOSIX, true},
		{"builtin eval", "f() { rm -rf /; }; builtin eval 'f'", DialectPOSIX, destructivePOSIX, true},
		{"time", "f() { rm -rf /; }; time f", DialectPOSIX, destructivePOSIX, true},
		// Loop round 3: a function defined in a separate shell stays there.
		{"subshell definition", "( f() { rm -rf /; }; ); f", DialectPOSIX, destructivePOSIX, false},
		{"pipeline stage definition", "f() { rm -rf /; } | cat; f", DialectPOSIX, destructivePOSIX, false},
		{"pipeline stage definition then a stage", "f() { echo ok; } | rm -rf /", DialectPOSIX, destructivePOSIX, true},
		{"later pipeline stage definition", "echo ok | f() { rm -rf /; }; f", DialectPOSIX, destructivePOSIX, false},
		{"substitution definition", "x=$(f() { rm -rf /; }); f", DialectPOSIX, destructivePOSIX, false},
		{"background definition", "f() { rm -rf /; } & f", DialectPOSIX, destructivePOSIX, false},
		{"subshell export", "( f() { rm -rf /; }; export -f f ); bash -c f", DialectPOSIX, destructivePOSIX, false},
		{"subshell export of a parent function", "f() { rm -rf /; }; ( export -f f ); bash -c f", DialectPOSIX, destructivePOSIX, false},
		{"call inside the subshell", "( f() { rm -rf /; }; f )", DialectPOSIX, destructivePOSIX, true},
		{"group definition", "{ f() { rm -rf /; }; }; f", DialectPOSIX, destructivePOSIX, true},
		{"if body definition", "if true; then f() { rm -rf /; }; fi; f", DialectPOSIX, destructivePOSIX, true},
		{"subshell redefinition", "f() { rm -rf /; }; ( f() { echo ok; }; ); f", DialectPOSIX, destructivePOSIX, true},
		// Loop round 3: a scriptblock value through inert pipeline consumers.
		{"scriptblock to Out-Null", `{ Remove-Item -Recurse -Force C:\ } | Out-Null`, DialectPowerShell, destructivePS, false},
		{"scriptblock through inert stages", `{ Remove-Item -Recurse -Force C:\ } | Out-String | Out-Null; Write-Output a`, DialectPowerShell, destructivePS, false},
		{"multiline scriptblock to Out-Null", "{\n  Remove-Item -Recurse -Force C:\\\n} | Out-Null", DialectPowerShell, destructivePS, false},
		{"scriptblock to Out-Null in if body", `if ($true) { { Remove-Item -Recurse -Force C:\ } | Out-Null }`, DialectPowerShell, destructivePS, false},
		{"scriptblock to a member consumer", `{ Remove-Item -Recurse -Force C:\ } | ForEach-Object -MemberName Invoke`, DialectPowerShell, destructivePS, true},
		{"scriptblock through an inert stage to a consumer", `{ Remove-Item -Recurse -Force C:\ } | Write-Output | ForEach-Object Invoke`, DialectPowerShell, destructivePS, true},
		{"scriptblock to a consumer alias", `{ Remove-Item -Recurse -Force C:\ } | % Invoke`, DialectPowerShell, destructivePS, true},
		{"scriptblock to a variable stage", `{ Remove-Item -Recurse -Force C:\ } | Out-Null $x`, DialectPowerShell, destructivePS, true},
		// Loop round 1 of continuation 3 (balanced defaults): more spellings
		// in which a function name or a scriptblock is only data.
		{"exported name in echo data", "f() { rm -rf /; }; export -f f; echo bash f", DialectPOSIX, destructivePOSIX, false},
		{"exported name in git data", "f() { rm -rf /; }; export -f f; git log --grep f", DialectPOSIX, destructivePOSIX, false},
		{"exported function and a build tool", "f() { rm -rf /; }; export -f f; make test", DialectPOSIX, destructivePOSIX, false},
		{"lookup builtins", "f() { rm -rf /; }; hash f; type -a f; declare -f f", DialectPOSIX, destructivePOSIX, false},
		{"lookup through command and builtin", "f() { rm -rf /; }; command -p -v f; builtin type f", DialectPOSIX, destructivePOSIX, false},
		{"alias of the name", "f() { rm -rf /; }; alias f=ls; echo f", DialectPOSIX, destructivePOSIX, false},
		{"assigned name as data", "f() { rm -rf /; }; x=f; echo $x", DialectPOSIX, destructivePOSIX, false},
		{"subshell export before the definition", "( export -f f 2>/dev/null; f() { rm -rf /; } ); f", DialectPOSIX, destructivePOSIX, false},
		{"scriptblock assigned to a variable", `$sb = { Remove-Item -Recurse -Force C:\ }; Write-Output done`, DialectPowerShell, destructivePS, false},
		{"scriptblock assigned to null", `$null = { Remove-Item -Recurse -Force C:\ }`, DialectPowerShell, destructivePS, false},
		{"scriptblock cast to void", `[void]{ Remove-Item -Recurse -Force C:\ }`, DialectPowerShell, destructivePS, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cwd, home := "/repo", "/home/alice"
			if tt.dialect == DialectPowerShell {
				cwd, home = `C:\repo`, `C:\Users\alice`
			}
			input := Input{Tool: "shell", Command: tt.command, CWD: cwd, ActiveHome: home, DialectHint: tt.dialect}
			got := SimpleCommands(input, Analyze(input))
			ran := slices.ContainsFunc(got, func(child SimpleCommand) bool { return child.Text == tt.want })
			if ran != tt.ran {
				t.Errorf("child %q exposed = %v, want %v: %#v", tt.want, ran, tt.ran, got)
			}
		})
	}
}
