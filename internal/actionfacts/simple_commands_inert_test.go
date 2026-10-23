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
