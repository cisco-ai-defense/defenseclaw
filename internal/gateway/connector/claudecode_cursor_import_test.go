// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"reflect"
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

// A missing small guard leaves no command that can distinguish a launcher
// start failure from a policy answer. Setup must refuse that registration.
func TestWindowsClaudeCodeWithoutAnInstalledGuardIsNotPublished(t *testing.T) {
	for _, launcher := range []string{
		`C:\Users\dcw-std1\.local\bin\defenseclaw-hook.exe`,
		`C:\Users\Jane Doe\.local\bin\defenseclaw-hook.exe`,
	} {
		t.Run(launcher, func(t *testing.T) {
			pinClaudeCodePreToolGuard(t, "")
			previous := claudeChainFor
			claudeChainFor = func(string) (string, string) { return "", "" }
			t.Cleanup(func() { claudeChainFor = previous })
			command, args := claudeCodeWindowsHookInvocation(SetupOpts{HookExecutable: launcher}, launcher)
			prompt, promptArgs := claudeCodeHandlerInvocation("UserPromptSubmit", command, args)
			if prompt != "" || promptArgs != nil {
				t.Fatalf("incomplete chain produced a prompt command: %q %q", prompt, promptArgs)
			}
			pretool, pretoolArgs := claudeCodeHandlerInvocation("PreToolUse", command, args)
			if pretool != launcher || !reflect.DeepEqual(pretoolArgs, []string{"hook", "--connector", "claudecode"}) {
				t.Fatalf("Cursor-compatible pretool fallback = %q %q", pretool, pretoolArgs)
			}
			// Earlier releases wrote the presence-only form on the other
			// events. It remains owned for teardown and rollback, but cannot
			// pass current verification as a new registration.
			hooks := map[string]interface{}{}
			hookArgs := []string{"hook", "--connector", "claudecode"}
			for _, group := range hookGroups {
				oldCommand, oldArgs := command, args
				if group.eventType == "PreToolUse" {
					oldCommand, oldArgs = launcher, hookArgs
				}
				handler := map[string]interface{}{"type": "command", "command": oldCommand, "args": oldArgs, "timeout": group.timeout}
				if group.async {
					handler["async"] = true
				}
				entry := map[string]interface{}{"hooks": []interface{}{handler}}
				if group.matcher != "" {
					entry["matcher"] = group.matcher
				}
				existing, _ := hooks[group.eventType].([]interface{})
				hooks[group.eventType] = append(existing, entry)
			}
			if err := verifyClaudeCodeHookGroups(hooks, command, args, "", hookGroups); err == nil {
				t.Fatal("the legacy no-guard registration passed current verification")
			}
			settings := map[string]interface{}{"hooks": hooks}
			owned := func(path string) bool { return path == launcher }
			if changed := claudeCodeHooksInEarlierReleaseForm(settings, "windows", "", owned); changed != len(hookGroups)-1 {
				t.Fatalf("rollback converted %d handlers, want %d", changed, len(hookGroups)-1)
			}
			for _, group := range hookGroups {
				handler := claudeHandlersOf(t, hooks, group.eventType)[0]
				if handler["command"] != launcher || !codexValueMatches(handler["args"], hookArgs) {
					t.Fatalf("%s after rollback = %#v", group.eventType, handler)
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
		{"guard on UserPromptSubmit", "UserPromptSubmit", guardCommand, guardArgs, "", nil},
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
	// With the installed hook of a packaged install, that program answers
	// the generated guard form for every event until Setup publishes a chain.
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
		{"guard on UserPromptSubmit", "UserPromptSubmit", guardCommand, guardArgs, guard,
			claudeGuardEventArgs(launcher, hookArgs, "UserPromptSubmit", false)},
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
