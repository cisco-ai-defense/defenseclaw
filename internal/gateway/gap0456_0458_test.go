// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// TestGAP0456OverBudgetWrappers checks the same statement limit for a
// direct command and for calls through functions and nested shells.
func TestGAP0456OverBudgetWrappers(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("POSIX home fixture requires an unprivileged Unix user")
	}
	homes := filepath.Join(t.TempDir(), "homes")
	home := filepath.Join(homes, "alice")
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	gap0568StateFile(t, home)
	t.Setenv("HOME", home)
	t.Cleanup(func() { _ = os.Chmod(homes, 0o700) })
	pad := gap0568Assignments(200)
	state := "~/.defenseclaw/config.yaml"
	rows := []struct {
		name, command string
		over          bool
	}{
		{"direct shell", pad + "; sh -c 'printf c >> " + state + "'", true},
		{"function shell", `run() { "$@"; }; ` + pad + "; run sh -c 'printf c >> " + state + "'", true},
		{"function chmod", `run() { "$@"; }; ` + pad + "; run chmod 777 " + state, true},
		{"nested functions", `outer() { inner "$@"; }; inner() { "$@"; }; ` + pad + "; outer sh -c 'printf c >> " + state + "'", true},
		{"benign function", `run() { "$@"; }; ` + pad + "; run git status", true},
		{"benign at bound", `run() { "$@"; }; ` + gap0568Assignments(126) + "; run git status", false},
	}
	for _, row := range rows {
		facts := actionfacts.Analyze(actionfacts.Input{Tool: "Bash", Command: row.command,
			CWD: cwd, ActiveHome: home, DialectHint: actionfacts.DialectPOSIX})
		if (facts.Parse.Status == actionfacts.StatusLimitExceeded) != row.over || actionfacts.ShellStatementsOverBudget(row.command) != row.over {
			t.Errorf("%s: status=%s budget=%t, want %t", row.name, facts.Parse.Status, actionfacts.ShellStatementsOverBudget(row.command), row.over)
		}
		findings := dispatchTrustedAction(context.Background(), trustedActionRequest{
			Input: actionfacts.Input{Tool: "Bash", Command: row.command, CWD: cwd, ActiveHome: home,
				DialectHint: actionfacts.DialectPOSIX},
			Connector: "claudecode", EnforcementCapable: true,
		})
		if got := findingWithID(findings, "ACTION-COMPOUND-LIMIT") != nil; got != row.over {
			t.Errorf("%s: budget finding=%t, want %t", row.name, got, row.over)
		}
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, mode := range []string{"action", "observe"} {
			api := instructionProtectionTestAPIWithPack(t, connector, mode, "HIGH", "strict")
			for _, cell := range []struct{ client, managed bool }{{false, false}, {true, false}, {true, true}} {
				for _, row := range rows {
					got := gap0568HookAction(t, api, connector, home, cwd, row.command, cell.client, cell.managed)
					if mode == "action" && (got == "block") != row.over || mode == "observe" && strings.HasPrefix(row.name, "benign") && got == "block" {
						t.Errorf("%s/%s client=%t managed=%t %s: %s", connector, mode, cell.client, cell.managed, row.name, got)
					}
				}
			}
		}
	}
}

// A function call that writes the active state has the same self-protection
// verdict as the direct call, including when the policy reading is over its
// statement budget. The four hook cells cover both connectors and both home
// visibility models.
func TestGAP0456WrappedStateWriteVerdictParity(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("POSIX home fixture requires an unprivileged Unix user")
	}
	homes := filepath.Join(t.TempDir(), "homes")
	home := filepath.Join(homes, "alice")
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	gap0568StateFile(t, home)
	t.Setenv("HOME", home)
	t.Cleanup(func() { _ = os.Chmod(homes, 0o700) })
	state := "~/.defenseclaw/config.yaml"
	pad := gap0568Assignments(200)
	rows := []struct{ name, command string }{
		{"direct", pad + "; sh -c 'printf c >> " + state + "'"},
		{"wrapped boundary", `run() { "$@"; }; ` + gap0568Assignments(129) + `; run sh -c 'printf c >> ` + state + `'`},
		{"wrapped", `run() { "$@"; }; ` + pad + "; run sh -c 'printf c >> " + state + "'"},
		{"variable wrapper", `run() { "$@"; }; f=run; ` + pad + `; "$f" sh -c 'printf c >> ` + state + `'`},
		{"shadowed echo", `echo() { printf c >> "$1"; }; log() { echo "$1"; }; ` + pad + "; log " + state},
		{"shadowed writer", `printf() { command printf c >> "$1"; }; log() { printf "$1"; }; ` + pad + "; log " + state},
		{"wrapped short", `run() { "$@"; }; run sh -c 'printf c >> ` + state + `'`},
		{"wrapped short after read", `run() { "$@"; }; true; run sh -c 'printf c >> ` + state + `'`},
		{"wrapped two statements", `run() { :; "$@"; }; run sh -c 'printf c >> ` + state + `'`},
		{"wrapped two statements after read", `run() { :; "$@"; }; true; run sh -c 'printf c >> ` + state + `'`},
		{"shadowed short", `printf() { command printf c >> "$1"; }; log() { printf "$1"; }; log ` + state},
		{"shadowed short echo", `echo() { printf c >> "$1"; }; log() { echo "$1"; }; log ` + state},
		{"conditional wrapper", `run() { if true; then "$@"; fi; }; run sh -c 'printf c >> ` + state + `'`},
	}
	benign := []string{
		`run() { "$@"; }; ` + pad + `; run sh -c 'echo ok'`,
		`run() { :; "$@"; }; run sh -c 'echo ok'`,
		`run() { "$@"; }; true; run cat ` + state,
		`log() { echo "$1"; }; ` + pad + `; log ` + state,
		`printf() { command printf c >> "$1"; }; ` + pad + `; echo ` + state,
	}
	shortBenign := []string{
		`run() { "$@"; }; run sh -c 'echo ok'`,
		`run() { :; "$@"; }; true; run sh -c 'echo ok'`,
		`run() { "$@"; }; run sh -c 'printf c >> out.txt'`,
		`run() { "$@"; }; run sh -c 'printf c >> ~/.defenseclaw/notes.txt'`,
		`echo() { printf c >> "$1"; }; log() { echo "$1"; }; log out.txt`,
		`run() { if true; then "$@"; fi; }; run sh -c 'printf c >> out.txt'`,
		`run() { if true; then "$@"; fi; }; run cat ` + state,
		`run() { if false; then "$@"; fi; }; run sh -c 'printf c >> ` + state + `'`,
		`run() { "$@"; }; run sh -c 'if false; then printf c >> ` + state + `; fi'`,
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, managed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/managed=%t", connector, managed), func(t *testing.T) {
				for _, policy := range []string{"default", "strict"} {
					for _, mode := range []string{"observe", "action"} {
						api := instructionProtectionTestAPI(t, connector, mode, "HIGH")
						api.scannerCfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), policy)
						for _, row := range rows {
							if got := gap0568HookAction(t, api, connector, home, cwd, row.command, true, managed); got != "block" {
								t.Errorf("%s/%s/%s: got %s, want block", policy, mode, row.name, got)
							}
						}
						for _, command := range shortBenign {
							if got := gap0568HookAction(t, api, connector, home, cwd, command, true, managed); got != "allow" {
								t.Errorf("%s/%s/ordinary %q: got %s, want allow", policy, mode, command, got)
							}
						}
						if mode == "observe" {
							for _, command := range benign {
								if got := gap0568HookAction(t, api, connector, home, cwd, command, true, managed); got != "allow" {
									t.Errorf("%s/%s/benign: got %s, want allow", policy, mode, got)
								}
							}
						}
					}
				}
			})
		}
	}
}

func TestGAP0456ForwardedChildBoundaryCells(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("POSIX home fixture requires an unprivileged Unix user")
	}
	homes := filepath.Join(t.TempDir(), "homes")
	home := filepath.Join(homes, "alice")
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	gap0568StateFile(t, home)
	t.Setenv("HOME", home)
	t.Cleanup(func() { _ = os.Chmod(homes, 0o700) })
	rows := []struct {
		name, command string
		block         bool
	}{
		{"static child at bound", `run() { "$@"; }; ` + gap0568Assignments(125) + `; run sh -c 'echo ok'`, false},
		{"static child over bound", `run() { "$@"; }; ` + gap0568Assignments(126) + `; run sh -c 'printf c >> ~/.defenseclaw/config.yaml'`, true},
		{"variable child at bound", `run() { "$@"; }; f=run; ` + gap0568Assignments(124) + `; "$f" sh -c 'echo ok'`, false},
		{"variable child over bound", `run() { "$@"; }; f=run; ` + gap0568Assignments(125) + `; "$f" sh -c 'printf c >> ~/.defenseclaw/config.yaml'`, true},
		{"multi-step child at bound", `run() { :; "$@"; }; ` + gap0568Assignments(124) + `; run sh -c 'echo ok'`, false},
		{"multi-step child over bound", `run() { :; "$@"; }; ` + gap0568Assignments(125) + `; run sh -c 'printf c >> ~/.defenseclaw/config.yaml'`, true},
	}
	for _, row := range rows {
		if got := actionfacts.ShellStatementsOverBudget(row.command); got != row.block {
			t.Errorf("%s: budget=%t, want %t", row.name, got, row.block)
		}
	}
	for _, connector := range []string{"claudecode", "codex"} {
		api := instructionProtectionTestAPI(t, connector, "action", "HIGH")
		for _, managed := range []bool{false, true} {
			for _, row := range rows {
				got := gap0568HookAction(t, api, connector, home, cwd, row.command, true, managed)
				if (got == "block") != row.block {
					t.Errorf("%s managed=%t %s: %s, want block=%t", connector, managed, row.name, got, row.block)
				}
			}
		}
	}
}

func TestGAP0448AndGAP0462Round9StateReadings(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("POSIX home fixture requires an unprivileged Unix user")
	}
	homes := filepath.Join(t.TempDir(), "homes")
	home := filepath.Join(homes, "alice")
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	gap0568StateFile(t, home)
	t.Setenv("HOME", home)
	t.Cleanup(func() { _ = os.Chmod(homes, 0o700) })
	steps := make([]string, 200)
	for i := range steps {
		steps[i] = fmt.Sprintf("Write-Host 'step %d'", i)
	}
	psPad := strings.Join(steps, "\n") + "\n"
	shPad := gap0568Assignments(200) + "; "
	state := "~/.defenseclaw/config.yaml"
	rows := []struct {
		name, command    string
		powerShell, hold bool
	}{
		{"block comment separator", psPad + "Get-Content " + state + " <# harmless ; note #>", true, false},
		{"block comment then writer", psPad + "Get-Content " + state + " <# harmless ; note #>; Set-Content -Path " + state + " -Value x", true, true},
		{"first block terminator then writer", psPad + "Get-Content " + state + " <# outer <# inner #>; Set-Content -Path " + state + " -Value x; #> Get-Content " + state, true, true},
		{"first block terminator then newline writer", psPad + "Get-Content " + state + " <# outer <# inner #>\nSet-Content -Path " + state + " -Value x\n#> Get-Content " + state, true, true},
		{"first block terminator then read", psPad + "Get-Content " + state + " <# outer <# inner #>; Get-Content notes.txt; #> Get-Content " + state, true, false},
		{"line comment separator", psPad + "Get-Content notes.txt # ; Set-Content " + state + " -Value x", true, false},
		{"line comment after list separator", psPad + "Get-Content notes.txt;# ; Set-Content " + state + " -Value x", true, false},
		{"line comment then writer", psPad + "Get-Content notes.txt # ; ignored\nSet-Content -Path " + state + " -Value x", true, true},
		{"unrelated date", psPad + "Get-Date; Get-Content " + state, true, false},
		{"unrelated sleep", psPad + "Start-Sleep -Milliseconds 1; Get-Content " + state, true, false},
		{"literal overwrite", psPad + "$p = Join-Path $HOME '.defenseclaw/config.yaml'; $p = 'notes.txt'; Set-Content -Path $p -Value x", true, false},
		{"read overwrite", psPad + "$p = Get-Item " + state + "; $p = Join-Path $HOME 'notes.txt'; Set-Content -Path $p -Value x", true, false},
		{"out variable writer", psPad + "Get-Item " + state + " -OutVariable p; Set-Content -Path $p[0].FullName -Value x", true, true},
		{"out variable alias writer", psPad + "Get-Item " + state + " -ov p; Set-Content -Path $p[0].FullName -Value x", true, true},
		{"out variable overwritten", psPad + "Get-Item " + state + " -OutVariable p; Get-Item notes.txt -OutVariable p; Set-Content -Path $p[0].FullName -Value x", true, false},
		{"pipeline writer", psPad + "Get-Item " + state + " | ForEach-Object { Set-Content -Path $_.FullName -Value x }", true, true},
		{"pipeline writer continued", psPad + "Get-Item " + state + " |\nForEach-Object { Set-Content -Path $_.FullName -Value x }", true, true},
		{"pipeline PSItem writer", psPad + "Get-Item " + state + " | ForEach-Object { Set-Content -Path $PSItem.FullName -Value x }", true, true},
		{"pipeline select writer", psPad + "Get-Item " + state + " | Select-Object -ExpandProperty FullName | ForEach-Object { Set-Content -Path $_ -Value x }", true, true},
		{"pipeline where writer", psPad + "Get-Item " + state + " | Where-Object { Test-Path $_.FullName } | ForEach-Object { Set-Content -Path $_.FullName -Value x }", true, true},
		{"pipeline pass-through writer", psPad + "Get-Item " + state + " | ForEach-Object { $_.FullName } | ForEach-Object { Set-Content -Path $_ -Value x }", true, true},
		{"pipeline select read", psPad + "Get-Item " + state + " | Select-Object -ExpandProperty FullName | ForEach-Object { Test-Path $_ }", true, false},
		{"pipeline read", psPad + "Get-Item " + state + " | ForEach-Object { Test-Path $_.FullName }", true, false},
		{"pipeline read continued", psPad + "Get-Item " + state + " |\nForEach-Object { Test-Path $_.FullName }", true, false},
		{"logical or is not a pipeline", psPad + "Get-Item " + state + " || Get-Content notes.txt", true, false},
		{"pipeline discard", psPad + "Get-Item " + state + " | Out-Null", true, false},
		{"earlier function", `echo() { printf c >> "$1"; }; ` + shPad + "echo " + state, false, true},
		{"later function", shPad + "echo " + state + `; echo() { printf c >> "$1"; }`, false, false},
		{"later function repeated read", shPad + "echo " + state + "; echo " + state + `; echo() { printf c >> "$1"; }`, false, false},
		{"earlier alias", `alias echo='printf c >>'; ` + shPad + "echo " + state, false, true},
		{"later alias", shPad + "echo " + state + `; alias echo='printf c >>'`, false, false},
	}
	old := codexShellRunsPowerShell
	codexShellRunsPowerShell = true
	t.Cleanup(func() { codexShellRunsPowerShell = old })
	for _, row := range rows {
		_, overflow, ok := hookpaths.StateNamingReading(row.command, home, row.powerShell)
		if !ok || overflow != row.hold {
			t.Errorf("%s: reading ok=%t hold=%t, want %t", row.name, ok, overflow, row.hold)
		}
	}
	for _, connector := range []string{"claudecode", "codex"} {
		api := instructionProtectionTestAPI(t, connector, "observe", "HIGH")
		for _, managed := range []bool{false, true} {
			for _, row := range rows {
				tool := "Bash"
				if row.powerShell && connector == "claudecode" {
					tool = "PowerShell"
				}
				got := gap0568ToolHookAction(t, api, connector, tool, home, cwd, row.command, true, managed)
				wantBlock := managed && row.hold || row.name == "earlier function"
				if (got == "block") != wantBlock {
					t.Errorf("%s managed=%t %s: %s, want block=%t", connector, managed, row.name, got, wantBlock)
				}
			}
		}
	}
}

// TestGAP0458ReadNamesNeedStableBinding holds a state path behind
// ProtectHome when an earlier statement can change the read command's
// binding. The ordinary unmodified read remains the benign twin.
func TestGAP0458ReadNamesNeedStableBinding(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("POSIX home fixture requires an unprivileged Unix user")
	}
	homes := filepath.Join(t.TempDir(), "homes")
	home := filepath.Join(homes, "alice")
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	gap0568StateFile(t, home)
	t.Setenv("HOME", home)
	t.Cleanup(func() { _ = os.Chmod(homes, 0o700) })
	steps := make([]string, 200)
	for i := range steps {
		steps[i] = fmt.Sprintf("Write-Host 'step %d'", i)
	}
	pad := strings.Join(steps, "\n")
	state := "~/.defenseclaw/config.yaml"
	rows := []struct {
		name, command string
		hold          bool
	}{
		{"plain read", pad + "\nGet-Content " + state, false},
		{"alias", pad + "\nSet-Alias gc Set-Content -Force; gc -Path " + state + " -Value x", true},
		{"print alias", pad + "\nSet-Alias echo Set-Content -Force; echo -Path " + state + " -Value x", true},
		{"alias provider", pad + "\nSet-Item Alias:gc Set-Content -Force; gc -Path " + state + " -Value x", true},
		{"alias variable provider", pad + "\n$Alias:gc = 'Set-Content'; gc -Path " + state + " -Value x", true},
		{"function", pad + "\nfunction Get-Content { param($Path) Set-Content -Path $Path -Value x }; Get-Content -Path " + state, true},
		{"function provider", pad + "\nSet-Item Function:Get-Content { param($Path) Set-Content -Path $Path -Value x }; Get-Content -Path " + state, true},
		{"dynamic rebind", pad + "\nInvoke-Expression 'Set-Alias gc Set-Content'; gc -Path " + state + " -Value x", true},
		{"nested scope", pad + "\n& { Set-Alias gc Set-Content -Force; gc -Path " + state + " -Value x }", true},
		{"chained writer", pad + "\nGet-Content " + state + " && Set-Content " + state + " -Value x", true},
		{"chained read", pad + "\nGet-Content " + state + " && Write-Output done", false},
		// GAP-0462: a reader can yield a path used by a later writer.
		{"joined path write", pad + "\n$p = Join-Path $HOME '.defenseclaw/config.yaml'; Set-Content -Path $p -Value x", true},
		{"item path write", pad + "\n$p = Get-Item " + state + "; Set-Content -Path $p.FullName -Value x", true},
		{"joined path read", pad + "\n$p = Join-Path $HOME '.defenseclaw/config.yaml'; Test-Path $p", false},
		// GAP-0448: these syntactic read and print forms remain benign.
		{"block comment", pad + "\nGet-Content " + state + " <# (note) #>", false},
		{"quoted comment shape with subexpression", pad + "\nGet-Content \"" + state + "<#$(Set-Content -Path " + state + " -Value x)#>\"", true},
		{"line comment", pad + "\nGet-Content " + state + " # @note", false},
		{"quoted path expression", pad + "\nGet-Content -Path ('" + state + "')", false},
		{"stderr copy", pad + "\nGet-Content " + state + " 2>&1", false},
		{"quoted pipe", pad + "\nWrite-Output 'prefix | " + state + "'", false},
	}
	for _, row := range rows {
		_, overflow, ok := hookpaths.StateNamingReading(row.command, home, true)
		if !ok || overflow != row.hold {
			t.Errorf("%s: state reading ok=%t hold=%t, want %t", row.name, ok, overflow, row.hold)
		}
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, mode := range []string{"action", "observe"} {
			api := instructionProtectionTestAPIWithPack(t, connector, mode, "HIGH", "strict")
			for _, cell := range []struct{ client, managed bool }{{false, false}, {true, false}, {true, true}} {
				for _, row := range rows {
					tool := "PowerShell"
					if connector == "codex" {
						tool = "Bash"
						previous := codexShellRunsPowerShell
						codexShellRunsPowerShell = true
						t.Cleanup(func() { codexShellRunsPowerShell = previous })
					}
					got := gap0568ToolHookAction(t, api, connector, tool, home, cwd, row.command, cell.client, cell.managed)
					wantBlock := mode == "action" || mode == "observe" && cell.managed && row.hold
					if (got == "block") != wantBlock {
						t.Errorf("%s/%s client=%t managed=%t %s: %s, want block=%t", connector, mode, cell.client, cell.managed, row.name, got, wantBlock)
					}
				}
			}
		}
	}
}

// TestGAP0459ShadowedPOSIXRead checks the corresponding POSIX helper: a
// function that calls echo is not read-only after echo is redefined.
func TestGAP0459ShadowedPOSIXRead(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("POSIX home fixture requires an unprivileged Unix user")
	}
	homes := filepath.Join(t.TempDir(), "homes")
	home := filepath.Join(homes, "alice")
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	gap0568StateFile(t, home)
	t.Setenv("HOME", home)
	t.Cleanup(func() { _ = os.Chmod(homes, 0o700) })
	pad := gap0568Assignments(200)
	state := "~/.defenseclaw/config.yaml"
	rows := []struct {
		name, command string
		hold          bool
	}{
		{"print helper", `log() { echo "$1"; }; ` + pad + "; log " + state, false},
		{"shadowed echo", `echo() { printf c >> "$1"; }; log() { echo "$1"; }; ` + pad + "; log " + state, true},
		{"shadowed printf", `printf() { /usr/bin/tee "$1"; }; log() { printf "$1"; }; ` + pad + "; log " + state, true},
		{"spaced read function", `echo () { printf c >> "$1"; }; ` + pad + "; echo " + state, true},
		{"static alias", `alias echo='printf c >>'` + "\n" + pad + "; echo " + state, true},
		{"dynamic alias", `name=echo; alias "$name=printf c >>"` + "\n" + pad + "; echo " + state, true},
		{"command alias", `command alias echo='printf c >>'` + "\n" + pad + "; echo " + state, true},
		{"command eval", `command eval "alias echo='printf c >>'"` + "\n" + pad + "; echo " + state, true},
	}
	for _, row := range rows {
		_, overflow, ok := hookpaths.StateNamingReading(row.command, home, false)
		if !ok || overflow != row.hold {
			t.Errorf("%s: state reading ok=%t hold=%t, want %t", row.name, ok, overflow, row.hold)
		}
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, mode := range []string{"action", "observe"} {
			api := instructionProtectionTestAPIWithPack(t, connector, mode, "HIGH", "strict")
			for _, cell := range []struct{ client, managed bool }{{false, false}, {true, false}, {true, true}} {
				for _, row := range rows {
					got := gap0568HookAction(t, api, connector, home, cwd, row.command, cell.client, cell.managed)
					staticFunctionWrite := row.name == "shadowed echo" || row.name == "shadowed printf" || row.name == "spaced read function"
					wantBlock := mode == "action" || mode == "observe" && (cell.managed && row.hold || staticFunctionWrite)
					if (got == "block") != wantBlock {
						t.Errorf("%s/%s client=%t managed=%t %s: %s, want block=%t", connector, mode, cell.client, cell.managed, row.name, got, wantBlock)
					}
				}
			}
		}
	}
}
