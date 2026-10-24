// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"slices"
	"testing"
)

// W24 loop round 3 (balanced defaults): only a word that a known runner
// executes as shell text can call an exported function, and only a pipeline
// consumer that can evaluate its input exposes a scriptblock literal's body.
// An ordinary utility's arguments and a sink's arguments are data.
func TestSimpleCommandsDataArgumentsRunNothing(t *testing.T) {
	const destructivePOSIX, destructivePS = "rm -rf /", `Remove-Item -Recurse -Force C:\`
	for _, tt := range []struct {
		name, command string
		ran           bool
	}{
		{"grep pattern names a shell", "f() { rm -rf /; }; export -f f; /bin/grep -F 'bash f' README.md", false},
		{"grep pattern without a path", "f() { rm -rf /; }; export -f f; grep -e 'sh -c f' notes.txt", false},
		{"echo text", "f() { rm -rf /; }; export -f f; echo 'run bash f now'", false},
		{"printf data", `f() { rm -rf /; }; export -f f; printf '%s\n' "bash -c f"`, false},
		{"git message", "f() { rm -rf /; }; export -f f; git commit -m 'call bash f'", false},
		{"curl data", "f() { rm -rf /; }; export -f f; curl -d 'bash f' https://example.invalid", false},
		{"script argument of an interpreter", "f() { rm -rf /; }; export -f f; python3 tool.py --pattern 'bash f'", false},
		{"module argument of an interpreter", "f() { rm -rf /; }; export -f f; python3 -m pytest -k 'bash f'", false},
		{"node script argument", "f() { rm -rf /; }; export -f f; node build.js 'bash f'", false},
		{"awk program file", "f() { rm -rf /; }; export -f f; awk -f report.awk 'bash f'", false},
		{"sudo of a data utility", "f() { rm -rf /; }; export -f f; sudo grep 'bash f' /etc/hosts", false},
		{"interpreter inline code", `f() { rm -rf /; }; export -f f; python3 -c "import os; os.system('bash -c f')"`, true},
		{"interpreter attached inline code", `f() { rm -rf /; }; export -f f; perl -we 'system "f"'`, true},
		{"node eval", `f() { rm -rf /; }; export -f f; node --eval "require('child_process').execSync('f')"`, true},
		{"awk program text", `f() { rm -rf /; }; export -f f; awk 'BEGIN { system("f") }'`, true},
		{"awk source with a program file", `f() { rm -rf /; }; export -f f; gawk -f lib.awk -e 'BEGIN { system("f") }'`, true},
		{"git rebase exec", "f() { rm -rf /; }; export -f f; git rebase --exec 'bash -c f' main", true},
		{"git config pager", "f() { rm -rf /; }; export -f f; git -c 'core.pager=bash -c f' log", true},
		{"tar command option", "f() { rm -rf /; }; export -f f; tar -xf a.tar --to-command='bash -c f'", true},
		{"ssh proxy command", "f() { rm -rf /; }; export -f f; ssh -o 'ProxyCommand=bash -c f' host", true},
		{"tmux shell text", "f() { rm -rf /; }; export -f f; tmux new-session 'bash -c f'", true},
		{"sudo shell", "f() { rm -rf /; }; export -f f; sudo bash -c f", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			input := Input{Tool: "shell", Command: tt.command, CWD: "/repo", ActiveHome: "/home/alice", DialectHint: DialectPOSIX}
			got := SimpleCommands(input, Analyze(input))
			ran := slices.ContainsFunc(got, func(child SimpleCommand) bool { return child.Text == destructivePOSIX })
			if ran != tt.ran {
				t.Errorf("child %q exposed = %v, want %v: %#v", destructivePOSIX, ran, tt.ran, got)
			}
		})
	}
	for _, tt := range []struct {
		name, command string
		ran           bool
	}{
		{"variable in a quoted Write-Output value", `{ Remove-Item -Recurse -Force C:\ } | Write-Output "report$year.txt"`, false},
		{"subexpression in a quoted Out-File name", `{ Remove-Item -Recurse -Force C:\ } | Out-File "r$(Get-Date -Format yyyy).txt"`, false},
		{"bare variable Out-File name", `{ Remove-Item -Recurse -Force C:\ } | Out-File $path`, false},
		{"environment path", `{ Remove-Item -Recurse -Force C:\ } | Out-File -FilePath $env:TEMP\out.txt -Append`, false},
		{"variable in a quoted Out-File name", `{ Remove-Item -Recurse -Force C:\ } | Out-File "r$x.txt"`, false},
		{"splat to a sink", `{ Remove-Item -Recurse -Force C:\ } | Out-File @params`, false},
		{"variable argument to Out-Null", `{ Remove-Item -Recurse -Force C:\ } | Out-Null $x`, false},
		{"escaped character", "{ Remove-Item -Recurse -Force C:\\ } | Write-Output a`$b", false},
		{"redirect after a sink", `{ Remove-Item -Recurse -Force C:\ } | Out-String > out.txt`, false},
		{"quoted variable to a property consumer", `{ Remove-Item -Recurse -Force C:\ } | Format-Table "Name$x"`, false},
		{"variable as the stage", `{ Remove-Item -Recurse -Force C:\ } | $x`, true},
		{"call operator stage", `{ Remove-Item -Recurse -Force C:\ } | & $x`, true},
		{"variable property expression", `{ Remove-Item -Recurse -Force C:\ } | Format-Table $p`, true},
		{"splat to a property consumer", `{ Remove-Item -Recurse -Force C:\ } | Format-List @p`, true},
		{"sink then an invoking stage", `{ Remove-Item -Recurse -Force C:\ } | Write-Output "r$x" | ForEach-Object Invoke`, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			input := Input{Tool: "shell", Command: tt.command, CWD: `C:\repo`, ActiveHome: `C:\Users\alice`, DialectHint: DialectPowerShell}
			got := SimpleCommands(input, Analyze(input))
			ran := slices.ContainsFunc(got, func(child SimpleCommand) bool { return child.Text == destructivePS })
			if ran != tt.ran {
				t.Errorf("child %q exposed = %v, want %v: %#v", destructivePS, ran, tt.ran, got)
			}
		})
	}
}

// The stage decision itself, also for argument forms that the simple command
// reader does not flatten: true means the scriptblock value is not invoked.
func TestWindowsSimpleInertPipelineConsumers(t *testing.T) {
	for _, tt := range []struct {
		stages string
		inert  bool
	}{
		{` | Write-Output "report$year.txt"`, true},
		{` | Out-File "r$(Get-Date).txt"`, true},
		{` | Out-File (Join-Path $d 'out.txt')`, true},
		{` | Out-File @params`, true},
		{` | Out-Null $x`, true},
		{` | Out-File -FilePath $env:TEMP\out.txt -Append`, true},
		{` | Out-String > out.txt`, true},
		{" | Out-File a`$b.txt", true},
		{` | Format-Table "Name$x" Length`, true},
		{` | Out-File report@2026.txt; Write-Output a`, true},
		{` | Out-File -FilePath { $_.Invoke() }`, false},
		{` | Write-Output (1 | ForEach-Object { $_ })`, false},
		{` | Measure-Object -Property (Get-Props)`, false},
		{` | Format-Table @{e={ $_.Invoke() }}`, false},
		{` | Format-Table $p`, false},
		{` | Format-List @p`, false},
		{` | ConvertTo-Html -Property $p`, false},
		{` | $x`, false},
		{` | & $x`, false},
		{` | Write-Output "r$x" | ForEach-Object Invoke`, false},
		{` | Write-Output (`, false},
		{` | Write-Output "open`, false},
	} {
		if got := windowsSimpleInertPipeline([]rune(tt.stages), 0); got != tt.inert {
			t.Errorf("%q inert = %v, want %v", tt.stages, got, tt.inert)
		}
	}
}
