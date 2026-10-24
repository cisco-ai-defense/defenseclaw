// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// pinClaudeCodePreToolGuard makes guard the installed full hook the
// PreToolUse handler starts, as a packaged install resolves it.
func pinClaudeCodePreToolGuard(t *testing.T, guard string) {
	t.Helper()
	previous := claudeCodePreToolGuardExecutable
	claudeCodePreToolGuardExecutable = func(string) string { return guard }
	t.Cleanup(func() { claudeCodePreToolGuardExecutable = previous })
}

// A tool call of a Claude Code turn that started before antivirus removed the
// launcher ran without DefenseClaw's decision: the PreToolUse handler started
// the launcher itself, and Claude Code treats a failed start (ENOENT) as a
// non-blocking error. No per-user Windows handler may start the launcher
// directly; PreToolUse runs the installed full hook as a guard that blocks
// when the launcher is missing, and is not cmd.exe, which Cursor's
// argument-free import could not run (GAP-1011).
func TestWindowsClaudeCodePreToolUseGuardBlocksAMissingLauncherAndSuitsCursor(t *testing.T) {
	for _, tc := range []struct{ launcher, guard string }{
		{`C:\Users\dcw-std1\AppData\Local\DefenseClaw\HookRuntime\defenseclaw-hook.exe`,
			`C:\Users\dcw-std1\AppData\Local\Programs\DefenseClaw\bin\defenseclaw-hook.exe`},
		{`C:\Users\Jane Doe\AppData\Local\DefenseClaw\HookRuntime\defenseclaw-hook.exe`,
			`C:\Users\Jane Doe\AppData\Local\Programs\DefenseClaw\bin\defenseclaw-hook.exe`},
	} {
		t.Run(tc.launcher, func(t *testing.T) {
			pinClaudeCodePreToolGuard(t, tc.guard)
			hooks, guardCommand, guardArgs := renderedWindowsPerUserClaudeHooks(t, tc.launcher)
			hookArgs := []string{"hook", "--connector", "claudecode"}
			for _, group := range hookGroups {
				handler := claudeHandlersOf(t, hooks, group.eventType)[0]
				command, _ := handler["command"].(string)
				args, _ := claudeCodeNativeExecArguments(handler)
				if normalizeWindowsHookExecutable(command) == normalizeWindowsHookExecutable(tc.launcher) {
					t.Fatalf("%s starts the launcher itself; a missing launcher lets the call run", group.eventType)
				}
				if view := claudeCodeExecView(handler).(map[string]interface{}); view["command"] != tc.launcher ||
					!codexValueMatches(view["args"], hookArgs) {
					t.Fatalf("%s does not read as the launcher it runs: %#v", group.eventType, view)
				}
				if !cursorPreToolChecks[group.eventType] {
					continue
				}
				if normalizeWindowsHookExecutable(command) == normalizeWindowsHookExecutable(guardCommand) {
					t.Fatalf("%s runs cmd.exe; Cursor starts it without args and blocks every tool call", group.eventType)
				}
				want := []string{ClaudeCodeLauncherGuardSubcommand, tc.launcher, "hook", "--connector", "claudecode"}
				if command != tc.guard || !reflect.DeepEqual(args, want) {
					t.Fatalf("%s handler = %q %q, want the guard %q %q", group.eventType, command, args, tc.guard, want)
				}
				if launcher, gotArgs, ok := ClaudeCodeLauncherGuardArgv(args); !ok || launcher != tc.launcher ||
					!reflect.DeepEqual(gotArgs, hookArgs) {
					t.Fatalf("the guard binary does not accept the argv Setup writes: %q", args)
				}
			}
			if err := verifyClaudeCodeHookGroups(hooks, guardCommand, guardArgs, "", hookGroups); err != nil {
				t.Fatalf("Setup's own hooks fail its verification: %v", err)
			}
			// Earlier PreToolUse forms fail verification, so Setup on the
			// upgraded gateway's first start rewrites them: the cmd.exe guard
			// of 1.0.1 to 1.0.3 and the direct launcher.
			for name, form := range map[string][]interface{}{
				"cmd.exe guard":   {guardCommand, guardArgs},
				"direct launcher": {tc.launcher, hookArgs},
			} {
				old := map[string]interface{}{}
				appendClaudeCodeHookGroups(old, guardCommand, guardArgs, hookGroups)
				handler := claudeHandlersOf(t, old, "PreToolUse")[0]
				handler["command"], handler["args"] = form[0], form[1]
				if err := verifyClaudeCodeHookGroups(old, guardCommand, guardArgs, "", hookGroups); err == nil ||
					!strings.Contains(err.Error(), "PreToolUse") {
					t.Fatalf("an earlier %s PreToolUse handler passed verification (err %v)", name, err)
				}
			}
			// Rollback gives earlier releases the exec form they own.
			settings := map[string]interface{}{"hooks": hooks}
			owned := func(path string) bool { return path == tc.launcher }
			if changed := claudeCodeHooksInEarlierReleaseForm(settings, "windows", "", owned); changed != len(hookGroups) {
				t.Fatalf("rollback converted %d handlers, want %d", changed, len(hookGroups))
			}
			for _, group := range hookGroups {
				handler := claudeHandlersOf(t, hooks, group.eventType)[0]
				if handler["command"] != tc.launcher || !codexValueMatches(handler["args"], hookArgs) {
					t.Fatalf("%s after rollback = %#v, want the exec form", group.eventType, handler)
				}
			}
		})
	}
}

func TestClaudeCodePreToolGuardIsTheSeparateInstalledHookOfAPackagedInstall(t *testing.T) {
	dir := t.TempDir()
	stable := filepath.Join(dir, "HookRuntime", "defenseclaw-hook.exe")
	installed := filepath.Join(dir, "Programs", "DefenseClaw", "bin", "defenseclaw-hook.exe")
	for _, path := range []string{stable, installed} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("MZ"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	directory := filepath.Join(dir, "dir", "defenseclaw-hook.exe")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, launcher, stable, installed, want string
	}{
		{"packaged install", stable, stable, installed, installed},
		{"another launcher", filepath.Join(dir, "x", "defenseclaw-hook.exe"), stable, installed, ""},
		{"no stable launcher", stable, "", installed, ""},
		{"no installed hook path", stable, stable, "", ""},
		{"installed hook missing", stable, stable, filepath.Join(dir, "gone", "defenseclaw-hook.exe"), ""},
		{"installed hook is a directory", stable, stable, directory, ""},
		{"installed hook is the launcher", stable, stable, stable, ""},
		{"installed file is not the hook", stable, stable, filepath.Join(dir, "Programs", "DefenseClaw", "bin"), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := claudeCodePreToolGuardFor(tc.launcher, tc.stable, tc.installed); got != tc.want {
				t.Fatalf("= %q, want %q", got, tc.want)
			}
		})
	}
}

func TestClaudeCodeLauncherGuardArgvStartsOnlyTheClaudeHookOfADefenseClawLauncher(t *testing.T) {
	launcher := `C:\Users\u\AppData\Local\DefenseClaw\HookRuntime\defenseclaw-hook.exe`
	hookArgs := []string{"hook", "--connector", "claudecode"}
	if got, args, ok := ClaudeCodeLauncherGuardArgv(append([]string{"launcher-guard", launcher}, hookArgs...)); !ok ||
		got != launcher || !reflect.DeepEqual(args, hookArgs) {
		t.Fatalf("the generated argv was refused: %q %q %v", got, args, ok)
	}
	for name, args := range map[string][]string{
		"no arguments":         nil,
		"hook argv only":       hookArgs,
		"other subcommand":     {"guard", launcher, "hook", "--connector", "claudecode"},
		"relative launcher":    {"launcher-guard", `defenseclaw-hook.exe`, "hook", "--connector", "claudecode"},
		"other program":        {"launcher-guard", `C:\Windows\System32\cmd.exe`, "hook", "--connector", "claudecode"},
		"other connector":      {"launcher-guard", launcher, "hook", "--connector", "codex"},
		"managed flag":         {"launcher-guard", launcher, "hook", "--connector", "claudecode", "--enterprise-managed"},
		"post hook":            {"launcher-guard", launcher, "hook-post", "--connector", "claudecode"},
		"quoted launcher":      {"launcher-guard", `C:\a"b\defenseclaw-hook.exe`, "hook", "--connector", "claudecode"},
		"variable in launcher": {"launcher-guard", `C:\%TEMP%\defenseclaw-hook.exe`, "hook", "--connector", "claudecode"},
		"padded launcher":      {"launcher-guard", launcher + " ", "hook", "--connector", "claudecode"},
	} {
		if _, _, ok := ClaudeCodeLauncherGuardArgv(args); ok {
			t.Errorf("%s: %q was accepted", name, args)
		}
	}
	guard := `C:\Users\u\AppData\Local\Programs\DefenseClaw\bin\defenseclaw-hook.exe`
	exact := map[string]interface{}{"type": "command", "command": guard,
		"args": stringsToInterfaces(append([]string{"launcher-guard", launcher}, hookArgs...))}
	if got, _, ok := claudeCodeLauncherGuardParts(exact); !ok || got != launcher {
		t.Fatalf("the generated guard handler is not read as one: %q %v", got, ok)
	}
	for name, edit := range map[string]func(map[string]interface{}){
		"guard is the launcher": func(h map[string]interface{}) { h["command"] = launcher },
		"guard is cmd.exe":      func(h map[string]interface{}) { h["command"] = `C:\Windows\System32\cmd.exe` },
		"relative guard":        func(h map[string]interface{}) { h["command"] = "defenseclaw-hook.exe" },
		"args as a string":      func(h map[string]interface{}) { h["args"] = "launcher-guard " + launcher },
		"extra argument": func(h map[string]interface{}) {
			h["args"] = append(h["args"].([]interface{}), "--fail-open")
		},
	} {
		edited := map[string]interface{}{}
		for key, value := range exact {
			edited[key] = value
		}
		edited["args"] = append([]interface{}(nil), exact["args"].([]interface{})...)
		edit(edited)
		if _, _, ok := claudeCodeLauncherGuardParts(edited); ok {
			t.Errorf("%s: an edited guard was read as the generated one: %#v", name, edited)
		}
		if view := claudeCodeExecView(edited); !reflect.DeepEqual(view, edited) {
			t.Errorf("%s: an edited guard got the exec view %#v", name, view)
		}
	}
}
