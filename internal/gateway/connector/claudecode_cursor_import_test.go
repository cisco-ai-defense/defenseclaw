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

func TestWindowsClaudeCodePreToolUseRunsTheLauncherSoCursorImportsDoNotBlock(t *testing.T) {
	for _, launcher := range []string{
		`C:\Users\dcw-std1\.local\bin\defenseclaw-hook.exe`,
		`C:\Users\Jane Doe\.local\bin\defenseclaw-hook.exe`,
	} {
		t.Run(launcher, func(t *testing.T) {
			hooks, guardCommand, guardArgs := renderedWindowsPerUserClaudeHooks(t, launcher)
			hookArgs := []string{"hook", "--connector", "claudecode"}
			guarded := 0
			for _, group := range hookGroups {
				handlers := claudeHandlersOf(t, hooks, group.eventType)
				if len(handlers) != 1 {
					t.Fatalf("%s has %d handlers, want 1", group.eventType, len(handlers))
				}
				handler := handlers[0]
				command, _ := handler["command"].(string)
				args, ok := claudeCodeNativeExecArguments(handler)
				if !ok {
					t.Fatalf("%s handler has no exec args: %#v", group.eventType, handler)
				}
				if cursorPreToolChecks[group.eventType] {
					// What Cursor runs: the command alone.
					if strings.EqualFold(normalizeWindowsHookExecutable(command), normalizeWindowsHookExecutable(guardCommand)) {
						t.Fatalf("%s runs cmd.exe; Cursor starts it without args, gets its banner and blocks every tool call", group.eventType)
					}
					if command != launcher || !reflect.DeepEqual(args, hookArgs) {
						t.Fatalf("%s handler = %q %q, want the launcher %q %q", group.eventType, command, args, launcher, hookArgs)
					}
					continue
				}
				gotLauncher, gotArgs, isGuard := claudeCodeLauncherGuardParts(handler)
				if !isGuard || gotLauncher != launcher || !reflect.DeepEqual(gotArgs, hookArgs) {
					t.Fatalf("%s handler lost the missing-launcher guard: %#v", group.eventType, handler)
				}
				guarded++
			}
			for _, event := range []string{"UserPromptSubmit", "PermissionRequest"} {
				if _, _, ok := claudeCodeLauncherGuardParts(claudeHandlersOf(t, hooks, event)[0]); !ok {
					t.Fatalf("%s must keep the guard so a missing launcher still blocks each prompt (GAP-1091)", event)
				}
			}
			if guarded == 0 {
				t.Fatal("no event kept the launcher guard")
			}
			if err := verifyClaudeCodeHookGroups(hooks, guardCommand, guardArgs, "", hookGroups); err != nil {
				t.Fatalf("Setup's own hooks fail its verification: %v", err)
			}
			// What 1.0.1 to this release wrote: the guard on PreToolUse too.
			// Verification refuses it, so Setup on the upgraded gateway's
			// first start rewrites that handler.
			old := map[string]interface{}{}
			for _, group := range hookGroups {
				appendClaudeCodeHookGroups(old, guardCommand, guardArgs, []claudeCodeHookGroup{group})
				if cursorPreToolChecks[group.eventType] {
					handler := old[group.eventType].([]interface{})[0].(map[string]interface{})["hooks"].([]interface{})[0].(map[string]interface{})
					handler["command"], handler["args"] = guardCommand, guardArgs
				}
			}
			if err := verifyClaudeCodeHookGroups(old, guardCommand, guardArgs, "", hookGroups); err == nil ||
				!strings.Contains(err.Error(), "PreToolUse") {
				t.Fatalf("an earlier guard-form PreToolUse handler passed verification (err %v)", err)
			}
		})
	}
}

func TestClaudeCodeHandlerInvocationChangesOnlyAGeneratedGuardOnPreToolUse(t *testing.T) {
	t.Setenv("SystemRoot", `C:\Windows`)
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
}
