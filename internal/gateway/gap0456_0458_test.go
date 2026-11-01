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
			api := instructionProtectionTestAPI(t, connector, mode, "HIGH")
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
			api := instructionProtectionTestAPI(t, connector, mode, "HIGH")
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
			api := instructionProtectionTestAPI(t, connector, mode, "HIGH")
			for _, cell := range []struct{ client, managed bool }{{false, false}, {true, false}, {true, true}} {
				for _, row := range rows {
					got := gap0568HookAction(t, api, connector, home, cwd, row.command, cell.client, cell.managed)
					wantBlock := mode == "action" || mode == "observe" && cell.managed && row.hold
					if (got == "block") != wantBlock {
						t.Errorf("%s/%s client=%t managed=%t %s: %s, want block=%t", connector, mode, cell.client, cell.managed, row.name, got, wantBlock)
					}
				}
			}
		}
	}
}
