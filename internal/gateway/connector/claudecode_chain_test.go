// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookguard"
)

func TestClaudeCodeChainRendersEveryEventAndKeepsForeignCommands(t *testing.T) {
	launcher := `C:\Users\Owner\AppData\Local\DefenseClaw\HookRuntime\defenseclaw-hook.exe`
	guard := `C:\Users\Owner\AppData\Local\DefenseClaw\HookRuntime\claude-code-chain\defenseclaw-hook-guard.exe`
	approved := `C:\Users\Owner\AppData\Local\DefenseClaw\HookRuntime\claude-code-chain\defenseclaw-hook-guard.approved`
	previous := claudeChainFor
	claudeChainFor = func(string) (string, string) { return guard, approved }
	t.Cleanup(func() { claudeChainFor = previous })
	baseCommand, baseArgs := claudeCodeWindowsHookInvocation(SetupOpts{HookExecutable: launcher}, launcher)
	hookArgs := []string{"hook", "--connector", "claudecode"}
	if baseCommand != claudeCodeWindowsCommandProcessor() {
		t.Fatalf("base command = %q", baseCommand)
	}
	seen := map[string]bool{}
	for _, group := range claudeCodeAllHookGroups {
		if seen[group.eventType] {
			continue
		}
		seen[group.eventType] = true
		command, args := claudeCodeHandlerInvocation(group.eventType, baseCommand, baseArgs)
		handler := map[string]interface{}{"command": command, "args": args}
		if group.eventType == "PreToolUse" {
			if command != guard || !slices.Equal(args, claudeGuardEventArgs(launcher, hookArgs, "PreToolUse", false)) {
				t.Fatalf("PreToolUse = %q %q", command, args)
			}
		} else {
			if command != baseCommand || !slices.Equal(args, claudeGuardWrapperArgs(guard, approved, launcher, group.eventType, hookArgs)) {
				t.Fatalf("%s = %q %q", group.eventType, command, args)
			}
			if got, gotArgs, ok := claudeGuardWrapperParts(handler); !ok || got != launcher || !slices.Equal(gotArgs, hookArgs) {
				t.Fatalf("%s wrapper was not owned", group.eventType)
			}
			code := "2"
			if hookguard.NeutralEvent(group.eventType) {
				code = "1"
			}
			if args[len(args)-1] != code {
				t.Fatalf("%s unavailable answer = %q, want %s", group.eventType, args[len(args)-1], code)
			}
		}
		if got, gotArgs, ok := claudeCodeLauncherGuardParts(handler); !ok || got != launcher || !slices.Equal(gotArgs, hookArgs) {
			t.Fatalf("%s command was not recognized", group.eventType)
		}
		view, ok := claudeCodeExecView(handler).(map[string]interface{})
		if !ok || view["command"] != launcher {
			t.Fatalf("%s exec view = %#v", group.eventType, view)
		}
	}
	if len(seen) != 29 {
		t.Fatalf("rendered %d events, want 29", len(seen))
	}
	hooks := map[string]interface{}{}
	appendClaudeCodeHookGroups(hooks, baseCommand, baseArgs, claudeCodeAllHookGroups)
	settings := map[string]interface{}{"hooks": hooks}
	owned := func(path string) bool { return path == launcher }
	if changed := claudeCodeHooksInEarlierReleaseForm(settings, "windows", "", owned); changed != len(seen) {
		t.Fatalf("rollback converted %d handlers, want %d", changed, len(seen))
	}
	for event := range seen {
		handler := claudeHandlersOf(t, hooks, event)[0]
		if handler["command"] != launcher || !codexValueMatches(handler["args"], hookArgs) {
			t.Fatalf("%s rollback did not restore the earlier exec form: %#v", event, handler)
		}
	}

	ordinary := []string{"hook", "--connector", "claudecode", "--enterprise-managed"}
	if command, args := claudeCodeHandlerInvocation("UserPromptSubmit", launcher, ordinary); command != launcher || !reflect.DeepEqual(args, ordinary) {
		t.Fatal("managed command changed")
	}
	edited := append(slices.Clone(baseArgs), "unexpected")
	if command, args := claudeCodeHandlerInvocation("UserPromptSubmit", baseCommand, edited); command != baseCommand || !slices.Equal(args, edited) {
		t.Fatal("foreign command changed")
	}
	wrappedCommand, wrappedArgs := claudeCodeHandlerInvocation("UserPromptSubmit", baseCommand, baseArgs)
	wrappedArgs = slices.Clone(wrappedArgs)
	wrappedArgs[len(wrappedArgs)-1] = "0"
	if _, _, ok := claudeCodeLauncherGuardParts(map[string]interface{}{"command": wrappedCommand, "args": wrappedArgs}); ok {
		t.Fatal("an edited wrapper was accepted as owned")
	}
}

func TestClaudeCodeChainKeepsAnApprovedGuardAndRepairsItsWorkingCopy(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "chain")
	source := filepath.Join(t.TempDir(), windowsHookGuardBinaryName)
	launcher := filepath.Join(t.TempDir(), windowsHookBinaryName)
	if err := os.WriteFile(source, []byte("MZ guard one"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldDir, oldSource, oldProbe := claudeChainDir, claudeChainSource, claudeChainProbe
	claudeChainDir = func() string { return dir }
	claudeChainSource = func(string) string { return source }
	claudeChainProbe = func(path, _ string) error {
		body, err := os.ReadFile(path)
		if err != nil || strings.Contains(string(body), "bad") {
			return os.ErrInvalid
		}
		return nil
	}
	t.Cleanup(func() { claudeChainDir, claudeChainSource, claudeChainProbe = oldDir, oldSource, oldProbe })
	if err := ensureClaudeChain(launcher); err != nil {
		t.Fatal(err)
	}
	files := claudeChainFilesIn(dir)
	if guard, approved := claudeChainFor(launcher); guard != files.guard || approved != files.approved {
		t.Fatalf("chain = %q, %q", guard, approved)
	}
	if err := os.WriteFile(files.guard, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ensureClaudeChain(launcher); err != nil {
		t.Fatal(err)
	}
	if body, _ := os.ReadFile(files.guard); string(body) != "MZ guard one" {
		t.Fatalf("guard was not restored: %q", body)
	}
	if err := os.WriteFile(source, []byte("bad guard"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ensureClaudeChain(launcher); err != nil {
		t.Fatalf("an approved chain should survive an unusable new source: %v", err)
	}
	if body, _ := os.ReadFile(files.approved); string(body) != "MZ guard one" {
		t.Fatalf("approved guard changed: %q", body)
	}
}
