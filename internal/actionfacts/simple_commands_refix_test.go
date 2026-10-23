// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"slices"
	"testing"
)

func TestSimpleCommandsW24Continuation(t *testing.T) {
	for _, tt := range []struct {
		name, command, cwd, home string
		dialect                  Dialect
		want                     SimpleCommand
	}{
		{"PowerShell line continuation", "Get-ChildItem |\n Select-Object Name", `C:\repo`, `C:\Users\alice`, DialectPowerShell,
			SimpleCommand{Text: "Select-Object Name", CWD: `C:\repo`}},
		{"PowerShell destructive line continuation", "Get-ChildItem |\n Remove-Item -Recurse -Force C:\\", `C:\repo`, `C:\Users\alice`, DialectPowerShell,
			SimpleCommand{Text: `Remove-Item -Recurse -Force C:\`, CWD: `C:\repo`}},
		{"multiline shell body", "bash -c 'echo a\necho b'", "/repo", "/home/alice", DialectPOSIX,
			SimpleCommand{Text: "echo b", CWD: "/repo"}},
		{"multiline destructive shell body", "sh -c 'echo a\nrm -rf /'", "/repo", "/home/alice", DialectPOSIX,
			SimpleCommand{Text: "rm -rf /", CWD: "/repo"}},
		{"trap action calls function", "f() { rm -rf /; }; trap 'true; f' EXIT", "/repo", "/home/alice", DialectPOSIX,
			SimpleCommand{Text: "rm -rf /", CWD: "/repo"}},
		{"trap option calls function", "f() { rm -rf /; }; trap -- f EXIT", "/repo", "/home/alice", DialectPOSIX,
			SimpleCommand{Text: "rm -rf /", CWD: "/repo"}},
		{"exported function body", "f() { rm -rf /; }; export -f f; bash -c f", "/repo", "/home/alice", DialectPOSIX,
			SimpleCommand{Text: "rm -rf /", CWD: "/repo"}},
		{"second exported function body", "f() { echo okay; }; g() { rm -rf /; }; export -f f g; bash -c g", "/repo", "/home/alice", DialectPOSIX,
			SimpleCommand{Text: "rm -rf /", CWD: "/repo"}},
		{"env shell body", "env sh -c 'true && rm -rf /'", "/repo", "/home/alice", DialectPOSIX,
			SimpleCommand{Text: "rm -rf /", CWD: "/repo"}},
		{"sudo shell body", "sudo sh -c 'true && rm -rf /'", "/repo", "/home/alice", DialectPOSIX,
			SimpleCommand{Text: "rm -rf /", CWD: "/repo"}},
		{"dash shell body", "dash -c 'true && rm -rf /'", "/repo", "/home/alice", DialectPOSIX,
			SimpleCommand{Text: "rm -rf /", CWD: "/repo"}},
		{"login shell does not assume startup directory", `bash -lc 'cat .ssh/id_rsa'`, "/repo", "/home/alice", DialectPOSIX,
			SimpleCommand{Text: "cat .ssh/id_rsa"}},
		{"bash named option", "bash -o pipefail -c 'true && rm -rf /'", "/repo", "/home/alice", DialectPOSIX,
			SimpleCommand{Text: "rm -rf /", CWD: "/repo"}},
		{"builtin directory", "builtin cd /home/alice && cat .ssh/id_rsa", "/repo", "/home/alice", DialectPOSIX,
			SimpleCommand{Text: "cat .ssh/id_rsa", CWD: "/home/alice"}},
		{"command directory", "command cd /home/alice && cat .ssh/id_rsa", "/repo", "/home/alice", DialectPOSIX,
			SimpleCommand{Text: "cat .ssh/id_rsa", CWD: "/home/alice"}},
		{"PowerShell directory", `Set-Location C:\Users\alice; Get-Content .ssh\id_rsa`, `C:\repo`, `C:\Users\alice`, DialectPowerShell,
			SimpleCommand{Text: `Get-Content .ssh\id_rsa`, CWD: `C:/Users/alice`}},
		{"cmd directory", `cd /d C:\Users\alice & type .ssh\id_rsa`, `C:\repo`, `C:\Users\alice`, DialectCMD,
			SimpleCommand{Text: `type .ssh\id_rsa`, CWD: `C:/Users/alice`}},
		{"cmd group", `if exist x (echo a & rmdir /s /q C:\)`, `C:\repo`, `C:\Users\alice`, DialectCMD,
			SimpleCommand{Text: `rmdir /s /q C:\`, CWD: `C:\repo`}},
		{"test builtin preserves directory", `if [ -f race.txt ]; then echo okay > out/result.txt; fi`, "/repo", "/home/alice", DialectPOSIX,
			SimpleCommand{Text: `echo okay > out/result.txt`, CWD: "/repo"}},
		{"PowerShell invoked block", `Write-Output a; & { Remove-Item -Recurse -Force C:\ }`, `C:\repo`, `C:\Users\alice`, DialectPowerShell,
			SimpleCommand{Text: `Remove-Item -Recurse -Force C:\`, CWD: `C:\repo`}},
		{"PowerShell if block", `if ($true) { Write-Output a; Remove-Item -Recurse -Force C:\ }`, `C:\repo`, `C:\Users\alice`, DialectPowerShell,
			SimpleCommand{Text: `Remove-Item -Recurse -Force C:\`, CWD: `C:\repo`}},
		{"PowerShell adjacent else block", `if ($true) { Write-Output a } else { Remove-Item -Recurse -Force C:\ }`, `C:\repo`, `C:\Users\alice`, DialectPowerShell,
			SimpleCommand{Text: `Remove-Item -Recurse -Force C:\`, CWD: `C:\repo`}},
		{"benign PowerShell group then read", `if ($true) { Write-Output a }; Get-Content ordinary.txt`, `C:\repo`, `C:\Users\alice`, DialectPowerShell,
			SimpleCommand{Text: `Get-Content ordinary.txt`, CWD: `C:\repo`}},
		{"conditional assignment quoted literally", `if ($false) { $target = 'C:\ordinary' }; Write-Output '$target'`, `C:\Users\alice`, `C:\Users\alice`, DialectPowerShell,
			SimpleCommand{Text: `Write-Output '$target'`, CWD: `C:\Users\alice`}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			input := Input{Tool: "shell", Command: tt.command, CWD: tt.cwd, ActiveHome: tt.home,
				DialectHint: tt.dialect}
			got := SimpleCommands(input, Analyze(input))
			if slices.ContainsFunc(got, func(child SimpleCommand) bool { return child.EvaluationFailure != "" }) ||
				!slices.Contains(got, tt.want) {
				t.Errorf("simple commands = %#v; want child %#v with no failure", got, tt.want)
			}
		})
	}
}

func TestSimpleCommandsW24UnprovenCases(t *testing.T) {
	for _, tt := range []struct {
		command, cwd string
		dialect      Dialect
	}{
		{"source ./env.sh; cat .ssh/id_rsa", "/repo", DialectPOSIX},
		{"bash -Z -c 'echo okay'", "/repo", DialectPOSIX},
		{`Set-Location $target; Get-Content .ssh\id_rsa`, `C:\repo`, DialectPowerShell},
		{`Write-Output a; { Remove-Item -Recurse -Force C:\`, `C:\repo`, DialectPowerShell},
		{`cd D:\ordinary & type .ssh\id_rsa`, `C:\Users\alice`, DialectCMD},
		{`if ($false) { Set-Location C:\ordinary }; Get-Content .ssh\id_rsa`, `C:\Users\alice`, DialectPowerShell},
		{`if exist x (cd /d D:\ordinary) & type .ssh\id_rsa`, `C:\Users\alice`, DialectCMD},
		{`if ($false) { $target = 'C:\ordinary' }; Get-Content $target`, `C:\Users\alice`, DialectPowerShell},
	} {
		input := Input{Tool: "shell", Command: tt.command, CWD: tt.cwd,
			ActiveHome: `C:\Users\alice`, DialectHint: tt.dialect}
		got := SimpleCommands(input, Analyze(input))
		if !slices.ContainsFunc(got, func(child SimpleCommand) bool { return child.EvaluationFailure == "parse" }) {
			t.Errorf("%q: expected a fail-closed parse result, got %#v", tt.command, got)
		}
	}
}

func TestSimpleCommandsActionBoundVariableProofBoundary(t *testing.T) {
	for _, tt := range []struct {
		name, command, child string
		bound                bool
	}{
		{"loop item", `for f in build/item.txt; do echo ok >> "$f"; done`, `echo ok >> "$f"`, true},
		{"command substitution", `out="$(mktemp -d)"; printf ok > "$out/probe.txt"`, `printf ok > "$out/probe.txt"`, true},
		{"export assignment", `export OUTPUT_DIR=out; printf ready > "$OUTPUT_DIR/status.txt"`, `printf ready > "$OUTPUT_DIR/status.txt"`, true},
		{"printf assignment", `printf -v f '%s' out/report.txt; echo ok >> "$f"`, `echo ok >> "$f"`, true},
		{"read assignment", `read f < report.txt; printf ok > "out/$f"`, `printf ok > "out/$f"`, true},
		{"function parameter", `stage_file() { cp "$1" "build/$2"; }; stage_file payload staged.bin`, `cp "$1" "build/$2"`, true},
		{"resolved assignment", `f=out/report.txt; echo ok >> "$f"`, `echo ok >> 'out/report.txt'`, false},
		{"unbound parameter", `echo okay; printf ok > "$target"`, `printf ok > "$target"`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			input := Input{Tool: "shell", Command: tt.command, CWD: "/repo", ActiveHome: "/home/alice", DialectHint: DialectPOSIX}
			children := SimpleCommands(input, Analyze(input))
			if !slices.ContainsFunc(children, func(child SimpleCommand) bool {
				return child.Text == tt.child && child.UnresolvedBoundVariable == tt.bound
			}) {
				t.Errorf("children=%#v; want %q bound=%v", children, tt.child, tt.bound)
			}
		})
	}
}

func TestSimpleCommandsWindowsStandaloneExpressionNeedsNoReduction(t *testing.T) {
	input := Input{Tool: "shell", Command: "Write-Output (Get-Date)",
		CWD: `C:\repo`, DialectHint: DialectPowerShell}
	if got := SimpleCommands(input, Analyze(input)); len(got) != 0 {
		t.Errorf("standalone expression produced compound children: %#v", got)
	}
}

func TestSimpleCommandsWindowsEmptyBlockNeedsNoReduction(t *testing.T) {
	input := Input{Tool: "shell", Command: `& { }`, CWD: `C:\repo`, DialectHint: DialectPowerShell}
	if got := SimpleCommands(input, Analyze(input)); len(got) != 0 {
		t.Errorf("empty script block produced compound children: %#v", got)
	}
}
