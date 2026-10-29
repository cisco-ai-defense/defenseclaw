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
		// The one-line install runs its GUI-subsystem guard beside the
		// launcher (GAP-1011 round 2, GAP-2467): the direct launcher let a
		// tool call of a turn that began before the launcher went missing
		// run uninspected.
		{`C:\Users\dcw-std1\.local\bin\defenseclaw-hook.exe`,
			`C:\Users\dcw-std1\.local\bin\defenseclaw-hook-guard.exe`},
		{`C:\Users\Jane Doe\.local\bin\defenseclaw-hook.exe`,
			`C:\Users\Jane Doe\.local\bin\defenseclaw-hook-guard.exe`},
		// A repository build has no guard file and runs its gateway.
		{`C:\Users\dcw-std1\.local\bin\defenseclaw-hook.exe`,
			`C:\Users\dcw-std1\.local\bin\defenseclaw-gateway.exe`},
		{`C:\Users\Jane Doe\.local\bin\defenseclaw-hook.exe`,
			`C:\Users\Jane Doe\.local\bin\defenseclaw-gateway.exe`},
	} {
		t.Run(tc.guard, func(t *testing.T) {
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

// The one-line install has no separate installed hook, so its PreToolUse
// handler ran the launcher directly: when antivirus removed the launcher after
// a turn's prompt was checked, the next tool call's start failed, which Claude
// Code treats as non-blocking, and the call ran uninspected (GAP-1011 round
// 2). Its guard was then the gateway beside the launcher, a console program:
// Claude Code started it without a console as a session ended, Windows gave it
// a console of its own and Windows Terminal opened a window that stayed with
// error 0x800700e8 (GAP-2467). The guard is now defenseclaw-hook-guard.exe, the
// hook built as its own GUI-subsystem file; only a layout without it (a
// repository build) runs the gateway, and any other layout keeps the exec form.
func TestClaudeCodePreToolGuardOfAOneLineInstallIsTheGUIGuardBesideTheLauncher(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, ".local", "bin")
	launcher := filepath.Join(bin, "defenseclaw-hook.exe")
	guard := filepath.Join(bin, "defenseclaw-hook-guard.exe")
	gateway := filepath.Join(bin, "defenseclaw-gateway.exe")
	repoBuild := filepath.Join(dir, "repo-build", "defenseclaw-hook.exe")
	repoGateway := filepath.Join(dir, "repo-build", "defenseclaw-gateway.exe")
	onlyHook := filepath.Join(dir, "only-hook", "defenseclaw-hook.exe")
	guardDir := filepath.Join(dir, "guard-dir", "defenseclaw-hook.exe")
	guardDirGateway := filepath.Join(dir, "guard-dir", "defenseclaw-gateway.exe")
	gatewayDir := filepath.Join(dir, "gateway-dir", "defenseclaw-hook.exe")
	other := filepath.Join(bin, "other.exe")
	for _, path := range []string{launcher, guard, gateway, repoBuild, repoGateway, onlyHook, guardDir, guardDirGateway, gatewayDir, other} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("MZ"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{
		filepath.Join(filepath.Dir(guardDir), "defenseclaw-hook-guard.exe"),
		filepath.Join(filepath.Dir(gatewayDir), "defenseclaw-gateway.exe"),
	} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct{ name, launcher, want string }{
		{"one-line install", launcher, guard},
		{"repository build without the guard file", repoBuild, repoGateway},
		{"guard is a directory", guardDir, guardDirGateway},
		{"no guard program beside the launcher", onlyHook, ""},
		{"gateway is a directory", gatewayDir, ""},
		{"launcher is not the hook", other, ""},
		{"relative launcher", "defenseclaw-hook.exe", ""},
		{"launcher cmd.exe cannot quote", filepath.Join(bin, "a%b", "defenseclaw-hook.exe"), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := claudeCodeOneLinePreToolGuardFor(tc.launcher); got != tc.want {
				t.Fatalf("= %q, want %q", got, tc.want)
			}
			// Without a packaged install the resolver Setup uses picks it too.
			if got := claudeCodePreToolGuardExecutable(tc.launcher); got != tc.want {
				t.Fatalf("PreToolUse guard = %q, want %q", got, tc.want)
			}
		})
	}
	// Only the hook, the guard and the gateway answer the launcher-guard argv.
	for path, want := range map[string]bool{
		guard: true, gateway: true, launcher: true,
		filepath.Join(bin, "defenseclaw-acp.exe"): false,
		filepath.Join(bin, "defenseclaw.exe"):     false,
		"defenseclaw-hook-guard.exe":              false,
		"defenseclaw-gateway.exe":                 false,
		`C:\Windows\System32\cmd.exe`:             false,
	} {
		if got := claudeCodePreToolGuardProgram(path); got != want {
			t.Fatalf("claudeCodePreToolGuardProgram(%q) = %v, want %v", path, got, want)
		}
	}
}

// A one-line install upgraded from a 1.0.5 release candidate still has the
// console gateway as its PreToolUse guard. That handler fails verification
// once the GUI guard is there, so Setup rewrites it to the guard, and until
// then it still reads as the launcher it runs (GAP-2467).
func TestClaudeCodeGatewayPreToolGuardIsRewrittenToTheGUIGuard(t *testing.T) {
	launcher := `C:\Users\dcw-std1\.local\bin\defenseclaw-hook.exe`
	guard := `C:\Users\dcw-std1\.local\bin\defenseclaw-hook-guard.exe`
	gateway := `C:\Users\dcw-std1\.local\bin\defenseclaw-gateway.exe`
	pinClaudeCodePreToolGuard(t, guard)
	hooks, guardCommand, guardArgs := renderedWindowsPerUserClaudeHooks(t, launcher)
	if err := verifyClaudeCodeHookGroups(hooks, guardCommand, guardArgs, "", hookGroups); err != nil {
		t.Fatalf("Setup's own hooks fail its verification: %v", err)
	}
	handler := claudeHandlersOf(t, hooks, "PreToolUse")[0]
	if handler["command"] != guard {
		t.Fatalf("PreToolUse command = %v, want the GUI guard %s", handler["command"], guard)
	}
	handler["command"] = gateway
	view := claudeCodeExecView(handler).(map[string]interface{})
	if view["command"] != launcher {
		t.Fatalf("the gateway guard does not read as its launcher: %#v", view)
	}
	if err := verifyClaudeCodeHookGroups(hooks, guardCommand, guardArgs, "", hookGroups); err == nil ||
		!strings.Contains(err.Error(), "PreToolUse") {
		t.Fatalf("the console gateway PreToolUse guard passed verification beside the GUI guard (err %v)", err)
	}
}
