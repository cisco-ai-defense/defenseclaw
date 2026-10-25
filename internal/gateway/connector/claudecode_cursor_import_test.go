// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// cursorPreToolChecks are the Claude Code events Cursor imports from
// ~/.claude/settings.json and runs as a check before a tool call. Cursor runs
// only an imported handler's command, without its args, and blocks the tool
// call when such a check answers with anything but JSON (GAP-1011). The other
// imported events (UserPromptSubmit, SessionStart, Stop, PostToolUse, ...) do
// not block on an invalid answer.
var cursorPreToolChecks = map[string]bool{"PreToolUse": true}

func renderedWindowsPerUserClaudeHooks(t *testing.T, launcher string) (map[string]interface{}, string, []string) {
	t.Helper()
	t.Setenv("SystemRoot", `C:\Windows`)
	command, args := claudeCodeWindowsHookInvocation(SetupOpts{HookExecutable: launcher}, launcher)
	if command != claudeCodeWindowsCommandProcessor() {
		t.Fatalf("per-user invocation command = %q, want the cmd.exe launcher guard", command)
	}
	hooks := map[string]interface{}{}
	appendClaudeCodeHookGroups(hooks, command, args, hookGroups)
	data, err := json.Marshal(hooks)
	if err != nil {
		t.Fatal(err)
	}
	decoded := map[string]interface{}{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded, command, args
}

func claudeHandlersOf(t *testing.T, hooks map[string]interface{}, event string) []map[string]interface{} {
	t.Helper()
	groups, _ := hooks[event].([]interface{})
	var handlers []map[string]interface{}
	for _, rawGroup := range groups {
		group, _ := rawGroup.(map[string]interface{})
		list, _ := group["hooks"].([]interface{})
		for _, raw := range list {
			handler, ok := raw.(map[string]interface{})
			if !ok {
				t.Fatalf("%s handler has type %T", event, raw)
			}
			handlers = append(handlers, handler)
		}
	}
	return handlers
}

// A launcher with no guard program beside it (a repository build: no
// separate installed hook and no defenseclaw-gateway.exe) has no PreToolUse
// guard to run. Its
// PreToolUse handler kept the cmd.exe guard, which Cursor imports from
// ~/.claude/settings.json and starts without arguments: cmd.exe answered with
// its banner instead of JSON and Cursor blocked every tool call, also with no
// Cursor hooks set up (GAP-1011, T11 TST-28456 and T12 TST-29761 on dc-win2).
// PreToolUse now runs the launcher in the exec form, which a start without
// arguments leaves without an answer; every other event keeps the cmd.exe
// guard, so a missing launcher still blocks the next prompt (GAP-1091). The
// cmd.exe guard of 1.0.1 to rc.10 on PreToolUse fails verification, so the
// upgraded gateway's Setup rewrites it, and a rollback gives earlier releases
// the exec form they own on every event.
func TestWindowsClaudeCodeWithoutAnInstalledHookRunsTheLauncherOnPreToolUse(t *testing.T) {
	for _, launcher := range []string{
		`C:\Users\dcw-std1\.local\bin\defenseclaw-hook.exe`,
		`C:\Users\Jane Doe\.local\bin\defenseclaw-hook.exe`,
	} {
		t.Run(launcher, func(t *testing.T) {
			pinClaudeCodePreToolGuard(t, "")
			hooks, guardCommand, guardArgs := renderedWindowsPerUserClaudeHooks(t, launcher)
			hookArgs := []string{"hook", "--connector", "claudecode"}
			for _, group := range hookGroups {
				handlers := claudeHandlersOf(t, hooks, group.eventType)
				if len(handlers) != 1 {
					t.Fatalf("%s has %d handlers, want 1", group.eventType, len(handlers))
				}
				command, _ := handlers[0]["command"].(string)
				args, _ := claudeCodeNativeExecArguments(handlers[0])
				if cursorPreToolChecks[group.eventType] {
					if normalizeWindowsHookExecutable(command) == normalizeWindowsHookExecutable(guardCommand) {
						t.Fatalf("%s runs cmd.exe; Cursor starts it without args and blocks every tool call", group.eventType)
					}
					if command != launcher || !reflect.DeepEqual(args, hookArgs) {
						t.Fatalf("%s handler = %q %q, want the launcher %q %q", group.eventType, command, args, launcher, hookArgs)
					}
					continue
				}
				gotLauncher, gotArgs, isGuard := claudeCodeCmdGuardParts(handlers[0])
				if !isGuard || gotLauncher != launcher || !reflect.DeepEqual(gotArgs, hookArgs) {
					t.Fatalf("%s handler lost the missing-launcher guard: %#v", group.eventType, handlers[0])
				}
			}
			if err := verifyClaudeCodeHookGroups(hooks, guardCommand, guardArgs, "", hookGroups); err != nil {
				t.Fatalf("Setup's own hooks fail its verification: %v", err)
			}
			// The cmd.exe guard an earlier release wrote on PreToolUse fails
			// verification, so Setup rewrites it on upgrade.
			old := map[string]interface{}{}
			appendClaudeCodeHookGroups(old, guardCommand, guardArgs, hookGroups)
			handler := claudeHandlersOf(t, old, "PreToolUse")[0]
			handler["command"], handler["args"] = guardCommand, guardArgs
			if err := verifyClaudeCodeHookGroups(old, guardCommand, guardArgs, "", hookGroups); err == nil ||
				!strings.Contains(err.Error(), "PreToolUse") {
				t.Fatalf("a cmd.exe PreToolUse handler passed verification (err %v)", err)
			}
			// Rollback converts the other events; PreToolUse is already the
			// exec form 1.0.0 owns.
			settings := map[string]interface{}{"hooks": hooks}
			owned := func(path string) bool { return path == launcher }
			if changed := claudeCodeHooksInEarlierReleaseForm(settings, "windows", "", owned); changed != len(hookGroups)-1 {
				t.Fatalf("rollback converted %d handlers, want %d", changed, len(hookGroups)-1)
			}
			for _, group := range hookGroups {
				handler := claudeHandlersOf(t, hooks, group.eventType)[0]
				if handler["command"] != launcher || !codexValueMatches(handler["args"], hookArgs) {
					t.Fatalf("%s after rollback = %#v, want the exec form", group.eventType, handler)
				}
			}
		})
	}
}

func TestClaudeCodeHandlerInvocationChangesOnlyAGeneratedGuardOnPreToolUse(t *testing.T) {
	t.Setenv("SystemRoot", `C:\Windows`)
	pinClaudeCodePreToolGuard(t, "")
	launcher := `C:\Users\u\.local\bin\defenseclaw-hook.exe`
	hookArgs := []string{"hook", "--connector", "claudecode"}
	guardCommand, guardArgs := claudeCodeWindowsHookInvocation(SetupOpts{HookExecutable: launcher}, launcher)
	managedArgs := append(append([]string(nil), hookArgs...), "--enterprise-managed")
	edited := append(append([]string(nil), guardArgs...), "&", "exit", "/b", "0")
	cases := []struct {
		name, event, command string
		args                 []string
		wantCommand          string
		wantArgs             []string
	}{
		{"guard on PreToolUse", "PreToolUse", guardCommand, guardArgs, launcher, hookArgs},
		{"guard on UserPromptSubmit", "UserPromptSubmit", guardCommand, guardArgs, guardCommand, guardArgs},
		{"managed exec form", "PreToolUse", launcher, managedArgs, launcher, managedArgs},
		{"unix script", "PreToolUse", "'/home/u/.defenseclaw/hooks/claude-code-hook.sh'", nil, "'/home/u/.defenseclaw/hooks/claude-code-hook.sh'", nil},
		{"edited guard", "PreToolUse", guardCommand, edited, guardCommand, edited},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			command, args := claudeCodeHandlerInvocation(tc.event, tc.command, tc.args)
			if command != tc.wantCommand || !reflect.DeepEqual(args, tc.wantArgs) {
				t.Fatalf("= %q %q, want %q %q", command, args, tc.wantCommand, tc.wantArgs)
			}
		})
	}
	// With the installed hook of a packaged install, the generated guard on
	// PreToolUse becomes the PreToolUse guard; everything else is unchanged.
	guard := `C:\Users\u\AppData\Local\Programs\DefenseClaw\bin\defenseclaw-hook.exe`
	pinClaudeCodePreToolGuard(t, guard)
	preToolArgs := []string{ClaudeCodeLauncherGuardSubcommand, launcher, "hook", "--connector", "claudecode"}
	for _, tc := range []struct {
		name, event, command string
		args                 []string
		wantCommand          string
		wantArgs             []string
	}{
		{"guard on PreToolUse", "PreToolUse", guardCommand, guardArgs, guard, preToolArgs},
		{"guard on UserPromptSubmit", "UserPromptSubmit", guardCommand, guardArgs, guardCommand, guardArgs},
		{"managed exec form", "PreToolUse", launcher, managedArgs, launcher, managedArgs},
		{"edited guard", "PreToolUse", guardCommand, edited, guardCommand, edited},
	} {
		t.Run("packaged/"+tc.name, func(t *testing.T) {
			command, args := claudeCodeHandlerInvocation(tc.event, tc.command, tc.args)
			if command != tc.wantCommand || !reflect.DeepEqual(args, tc.wantArgs) {
				t.Fatalf("= %q %q, want %q %q", command, args, tc.wantCommand, tc.wantArgs)
			}
		})
	}
}
