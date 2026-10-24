// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"slices"
	"testing"
)

// W24 loop round 4. unset removes a function the way bash does, and a
// command that runs only through a runtime choice the walk does not decide
// is exposed as Possible (GAP-0934, GAP-0935): its matches are strict-tier
// findings, never a default refusal.
func TestSimpleCommandsUnsetAndPossibleExecution(t *testing.T) {
	const destructivePOSIX, destructivePS = "rm -rf /", `Remove-Item -Recurse -Force C:\`
	const (
		absent = iota
		definite
		possible
	)
	for _, tt := range []struct {
		name, command string
		dialect       Dialect
		want          string
		exposed       int
	}{
		{"unset -f removes the function", "f() { rm -rf /; }; unset -f f; f", DialectPOSIX, destructivePOSIX, absent},
		{"unset without options removes the function", "f() { rm -rf /; }; unset f; f", DialectPOSIX, destructivePOSIX, absent},
		{"unset -f -- removes the function", "f() { rm -rf /; }; unset -f -- f; f", DialectPOSIX, destructivePOSIX, absent},
		{"unset -f of an exported function", "f() { rm -rf /; }; export -f f; unset -f f; bash -c f", DialectPOSIX, destructivePOSIX, absent},
		{"unset of a variable keeps the function", "f() { rm -rf /; }; f=1; unset f; f", DialectPOSIX, destructivePOSIX, definite},
		{"unset -v keeps the function", "f() { rm -rf /; }; unset -v f; f", DialectPOSIX, destructivePOSIX, definite},
		{"unset in a subshell keeps the function", "f() { rm -rf /; }; ( unset -f f ); f", DialectPOSIX, destructivePOSIX, definite},
		{"unset with -f and -v fails", "f() { rm -rf /; }; unset -fv f; f", DialectPOSIX, destructivePOSIX, definite},
		{"unset of another name", "f() { rm -rf /; }; unset -f g; f", DialectPOSIX, destructivePOSIX, definite},
		{"function called directly", "f() { rm -rf /; }; f", DialectPOSIX, destructivePOSIX, definite},
		{"assigned program word", "f() { rm -rf /; }; x=f; $x", DialectPOSIX, destructivePOSIX, possible},
		{"quoted assigned program word", `f() { rm -rf /; }; x=f; "$x"`, DialectPOSIX, destructivePOSIX, possible},
		{"braced assigned program word", "f() { rm -rf /; }; x=f; ${x} -v", DialectPOSIX, destructivePOSIX, possible},
		{"assigned program word in a list", "f() { rm -rf /; }; x=f && $x", DialectPOSIX, destructivePOSIX, possible},
		{"reassigned to another name", "f() { rm -rf /; }; g() { echo ok; }; x=f; x=g; $x", DialectPOSIX, destructivePOSIX, absent},
		{"assignment in a subshell is gone", "f() { rm -rf /; }; ( x=f ); $x", DialectPOSIX, destructivePOSIX, absent},
		{"loop variable is not a fixed name", "f() { rm -rf /; }; for x in f; do :; done; $x", DialectPOSIX, destructivePOSIX, absent},
		{"read variable is not a fixed name", "f() { rm -rf /; }; x=f; read x; $x", DialectPOSIX, destructivePOSIX, absent},
		{"literal condition body", `if ($true) { Remove-Item -Recurse -Force C:\ }`, DialectPowerShell, destructivePS, definite},
		{"command condition body", `if (Test-Path x) { Remove-Item -Recurse -Force C:\ }`, DialectPowerShell, destructivePS, possible},
		{"variable condition body", `if ($env:CI) { Remove-Item -Recurse -Force C:\ }`, DialectPowerShell, destructivePS, possible},
		{"comparison condition body", `if ($n -gt 0) { Remove-Item -Recurse -Force C:\ }`, DialectPowerShell, destructivePS, possible},
		{"else after a command condition", `if (Test-Path x) { Write-Output a } else { Remove-Item -Recurse -Force C:\ }`, DialectPowerShell, destructivePS, possible},
		{"elseif after a command condition", `if (Test-Path x) { Write-Output a } elseif ($true) { Remove-Item -Recurse -Force C:\ }`, DialectPowerShell, destructivePS, possible},
		{"while body", `while ($i -lt 3) { Remove-Item -Recurse -Force C:\ }`, DialectPowerShell, destructivePS, possible},
		{"foreach over a command", `foreach ($f in Get-ChildItem) { Remove-Item -Recurse -Force C:\ }`, DialectPowerShell, destructivePS, possible},
		{"statement after a condition runs", `if (Test-Path x) { Write-Output a }; Remove-Item -Recurse -Force C:\`, DialectPowerShell, destructivePS, definite},
		{"switch with a command header", `switch (Get-Item x) { 'a' { Remove-Item -Recurse -Force C:\ } }`, DialectPowerShell, destructivePS, absent},
		{"condition with a scriptblock", `if (Get-ChildItem | Where-Object { $_ }) { Remove-Item -Recurse -Force C:\ }`, DialectPowerShell, destructivePS, absent},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cwd, home := "/repo", "/home/alice"
			if tt.dialect == DialectPowerShell {
				cwd, home = `C:\repo`, `C:\Users\alice`
			}
			input := Input{Tool: "shell", Command: tt.command, CWD: cwd, ActiveHome: home, DialectHint: tt.dialect}
			got := SimpleCommands(input, Analyze(input))
			index := slices.IndexFunc(got, func(child SimpleCommand) bool { return child.Text == tt.want })
			exposed := absent
			if index >= 0 {
				exposed = definite
				if got[index].Possible {
					exposed = possible
				}
			}
			if exposed != tt.exposed {
				t.Errorf("child %q exposure = %d, want %d (0 absent, 1 definite, 2 possible): %#v", tt.want, exposed, tt.exposed, got)
			}
		})
	}
}
