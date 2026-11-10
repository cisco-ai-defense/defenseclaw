// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

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
			if args[len(args)-2] != code {
				t.Fatalf("%s unavailable answer = %q, want %s", group.eventType, args[len(args)-2], code)
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
	wrappedArgs[len(wrappedArgs)-2] = "0"
	if _, _, ok := claudeCodeLauncherGuardParts(map[string]interface{}{"command": wrappedCommand, "args": wrappedArgs}); ok {
		t.Fatal("an edited wrapper was accepted as owned")
	}
}

func TestManagedClaudeCodeWrapperAnswersEveryEvent(t *testing.T) {
	launcher := `C:\Program Files\DefenseClaw\bin\defenseclaw-hook.exe`
	guard := `C:\Program Files\DefenseClaw\bin\defenseclaw-hook-guard.exe`
	hookArgs := []string{"hook", "--connector", "claudecode", "--enterprise-managed"}
	seen := map[string]bool{}
	for _, group := range claudeCodeAllHookGroups {
		if seen[group.eventType] {
			continue
		}
		seen[group.eventType] = true
		command, args := claudeManagedGuardWrapperInvocation(group.eventType, launcher, hookArgs)
		if command != claudeCodeWindowsCommandProcessor() || !slices.Equal(args, claudeManagedGuardWrapperArgs(guard, launcher, group.eventType, hookArgs)) {
			t.Fatalf("%s managed handler = %q %q", group.eventType, command, args)
		}
		want := "2"
		if hookguard.NeutralEvent(group.eventType) {
			want = "1"
		}
		if args[len(args)-2] != want {
			t.Fatalf("%s unavailable exit = %q, want %s", group.eventType, args[len(args)-2], want)
		}
		handler := map[string]interface{}{"command": command, "args": args}
		if got, inner, ok := claudeCodeLauncherGuardParts(handler); !ok || got != launcher || !slices.Equal(inner, hookArgs) {
			t.Fatalf("%s managed wrapper is not owned", group.eventType)
		}
		view := claudeCodeExecView(handler).(map[string]interface{})
		if view["command"] != launcher || !codexValueMatches(view["args"], hookArgs) {
			t.Fatalf("%s managed exec view = %#v", group.eventType, view)
		}
	}
	if len(seen) != 29 {
		t.Fatalf("rendered %d managed events, want 29", len(seen))
	}
	command, args := claudeManagedGuardWrapperInvocation("UserPromptSubmit", launcher,
		[]string{"hook", "--connector", "claudecode"})
	if command != launcher || !slices.Equal(args, []string{"hook", "--connector", "claudecode"}) {
		t.Fatal("ordinary non-managed command changed")
	}
	if err := claudeCodeChainAdmission(SetupOpts{ManagedEnterprise: true},
		`C:\Program%Files\DefenseClaw\bin\defenseclaw-hook.exe`, hookArgs, "windows"); err == nil {
		t.Fatal("managed setup admitted a path cmd.exe would expand")
	}
}

// A per-user Setup that carries the managed flag writes the launcher's exec
// form into the user's settings: no cmd.exe wraps it, so any launcher path
// renders, and Setup must not refuse it as it refuses a managed-policy path
// that cmd.exe would expand.
func TestClaudeCodeChainAdmissionAcceptsTheExecFormOfAManagedPerUserSetup(t *testing.T) {
	launcher := `C:\Program%Files\DefenseClaw\bin\defenseclaw-hook.exe`
	perUser := []string{"hook", "--connector", "claudecode"}
	managed := SetupOpts{ManagedEnterprise: true}
	if err := claudeCodeChainAdmission(managed, launcher, perUser, "windows"); err != nil {
		t.Fatalf("exec form of a managed per-user setup refused: %v", err)
	}
	if err := claudeCodeChainAdmission(managed, launcher, append(slices.Clone(perUser), "--enterprise-managed"), "windows"); err == nil {
		t.Fatal("managed policy path that cmd.exe would expand was admitted")
	}
	if err := claudeCodeChainAdmission(managed, launcher, append(slices.Clone(perUser), "--unexpected"), "windows"); err == nil {
		t.Fatal("an unknown managed argument shape was admitted")
	}
}

// The enterprise status verifies the managed policy by reading each handler
// through ClaudeCodeManagedGuardLauncher, so it must read exactly the form the
// managed Setup renders for every event, and no edited one.
func TestClaudeCodeManagedGuardLauncherReadsTheRenderedManagedForm(t *testing.T) {
	launcher := `C:\Program Files\DefenseClaw\bin\defenseclaw-hook.exe`
	hookArgs := []string{"hook", "--connector", "claudecode", "--enterprise-managed"}
	for _, group := range claudeCodeAllHookGroups {
		command, args := claudeManagedGuardWrapperInvocation(group.eventType, launcher, hookArgs)
		raw := make([]interface{}, len(args))
		for i, arg := range args {
			raw[i] = arg
		}
		handler := map[string]interface{}{"type": "command", "command": command, "args": raw}
		got, gotArgs, ok := ClaudeCodeManagedGuardLauncher(handler)
		if !ok || got != launcher || !slices.Equal(gotArgs, hookArgs) {
			t.Fatalf("%s: managed form not read: %q %q %v", group.eventType, got, gotArgs, ok)
		}
		edited := append([]interface{}(nil), raw...)
		edited[len(edited)-2] = "0"
		if _, _, ok := ClaudeCodeManagedGuardLauncher(map[string]interface{}{"type": "command", "command": command, "args": edited}); ok {
			t.Fatalf("%s: an edited unavailable answer was read as the managed form", group.eventType)
		}
	}
	plain := map[string]interface{}{"type": "command", "command": launcher, "args": []interface{}{"hook", "--connector", "claudecode", "--enterprise-managed"}}
	if _, _, ok := ClaudeCodeManagedGuardLauncher(plain); ok {
		t.Fatal("the plain exec form was read as the guarded form")
	}
}

func TestManagedClaudeCodeSetupPublishesAvailabilityParent(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows managed registration")
	}
	launcher := `C:\Program Files\DefenseClaw\bin\defenseclaw-hook.exe`
	opts := SetupOpts{ManagedEnterprise: true, HookExecutable: launcher}
	groups, err := claudeCodeHookGroupsForSetup(opts)
	if err != nil {
		t.Fatal(err)
	}
	command, args := claudeCodeManagedHookInvocation(opts, `C:\ProgramData\DefenseClaw\hooks\claude-code-hook.sh`)
	hooks := map[string]interface{}{}
	if err := appendClaudeCodeHookMatrixForSetup(hooks, command, args, opts); err != nil {
		t.Fatal(err)
	}
	if err := verifyClaudeCodeHookMatrixForSetup(hooks, command, args, `C:\ProgramData\DefenseClaw\hooks`, opts); err != nil {
		t.Fatal(err)
	}
	for _, group := range groups {
		handler := claudeHandlersOf(t, hooks, group.eventType)[0]
		if handler["command"] != claudeCodeWindowsCommandProcessor() {
			t.Fatalf("%s registered %q", group.eventType, handler["command"])
		}
	}
	secureClient := opts
	secureClient.SecureClientHookDelivery = true
	secureHooks := map[string]interface{}{}
	if err := appendClaudeCodeHookMatrixForSetup(secureHooks, command, args, secureClient); err != nil {
		t.Fatal(err)
	}
	for _, group := range groups {
		handler := claudeHandlersOf(t, secureHooks, group.eventType)[0]
		if handler["command"] != launcher {
			t.Fatalf("Secure Client %s command changed", group.eventType)
		}
	}
}

func TestClaudeCodeChainRechecksSavedGuardModeBeforeReuse(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "chain")
	source := filepath.Join(t.TempDir(), windowsHookGuardBinaryName)
	launcher := filepath.Join(t.TempDir(), windowsHookBinaryName)
	if err := os.WriteFile(source, []byte("MZ current guard"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldDir, oldSource, oldProbe := claudeChainDir, claudeChainSource, claudeChainProbe
	claudeChainDir = func() string { return dir }
	claudeChainSource = func(string) string { return source }
	claudeChainProbe = func(string, string) error { return nil }
	t.Cleanup(func() { claudeChainDir, claudeChainSource, claudeChainProbe = oldDir, oldSource, oldProbe })
	if err := ensureClaudeChain(launcher); err != nil {
		t.Fatal(err)
	}
	claudeChainProbe = func(string, string) error { return fmt.Errorf("guard does not answer current mode") }
	if err := ensureClaudeChain(launcher); err == nil {
		t.Fatal("a saved guard without the current answer was reused")
	}
}

func TestClaudeCodeChainKeepsPackagedPreToolStartPath(t *testing.T) {
	launcher := `C:\Users\Owner\AppData\Local\DefenseClaw\HookRuntime\defenseclaw-hook.exe`
	installed := `C:\Program Files\DefenseClaw\bin\defenseclaw-hook.exe`
	guard := `C:\Users\Owner\AppData\Local\DefenseClaw\claude-code-chain\chain-abc123\defenseclaw-hook-guard.exe`
	approved := `C:\Users\Owner\AppData\Local\DefenseClaw\claude-code-chain\chain-abc123\defenseclaw-hook-guard.approved`
	oldChain, oldDirect := claudeChainFor, claudeCodePreToolGuardExecutable
	claudeChainFor = func(string) (string, string) { return guard, approved }
	claudeCodePreToolGuardExecutable = func(string) string { return installed }
	t.Cleanup(func() { claudeChainFor, claudeCodePreToolGuardExecutable = oldChain, oldDirect })
	baseCommand, baseArgs := claudeCodeWindowsHookInvocation(SetupOpts{HookExecutable: launcher}, launcher)
	command, args := claudeCodeHandlerInvocation("PreToolUse", baseCommand, baseArgs)
	if command != installed || !slices.Equal(args, claudeGuardEventArgs(launcher, []string{"hook", "--connector", "claudecode"}, "PreToolUse", false)) {
		t.Fatalf("packaged PreToolUse = %q %q", command, args)
	}
	command, args = claudeCodeHandlerInvocation("UserPromptSubmit", baseCommand, baseArgs)
	if command != baseCommand || !slices.Equal(args, claudeGuardWrapperArgs(guard, approved, launcher, "UserPromptSubmit", []string{"hook", "--connector", "claudecode"})) {
		t.Fatalf("ordinary event = %q %q", command, args)
	}
}

func TestClaudeCodeChainAvailabilityFollowsPolicyTier(t *testing.T) {
	launcher := `C:\Users\Owner\bin\defenseclaw-hook.exe`
	guard := `C:\Users\Owner\chain\chain-abc123\defenseclaw-hook-guard.exe`
	approved := `C:\Users\Owner\chain\chain-abc123\defenseclaw-hook-guard.approved`
	previous := claudeChainFor
	claudeChainFor = func(string) (string, string) { return guard, approved }
	t.Cleanup(func() { claudeChainFor = previous })
	baseCommand, baseArgs := claudeCodeWindowsHookInvocation(SetupOpts{}, launcher)
	hookArgs := []string{"hook", "--connector", "claudecode"}
	for _, tc := range []struct {
		name string
		opts SetupOpts
		open bool
	}{
		{"default", SetupOpts{}, true},
		{"permissive", SetupOpts{PolicyTier: "permissive"}, true},
		{"strict", SetupOpts{PolicyTier: "strict"}, false},
		{"managed", SetupOpts{ManagedEnterprise: true}, false},
		{"secure client", SetupOpts{SecureClientHookDelivery: true}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := claudeCodeUnavailableOpen(tc.opts); got != tc.open {
				t.Fatalf("open = %v, want %v", got, tc.open)
			}
			command, args := claudeCodeHandlerInvocation("UserPromptSubmit", baseCommand, baseArgs, tc.open)
			want := claudeGuardWrapperArgs(guard, approved, launcher, "UserPromptSubmit", hookArgs, tc.open)
			if command != baseCommand || !slices.Equal(args, want) {
				t.Fatalf("prompt handler = %q %q, want %q %q", command, args, baseCommand, want)
			}
			if args[len(args)-2] != map[bool]string{true: "1", false: "2"}[tc.open] {
				t.Fatalf("unavailable answer = %q", args[len(args)-2])
			}
			if got, _, ok := claudeGuardWrapperParts(map[string]interface{}{"command": command, "args": args}); !ok || got != launcher {
				t.Fatal("profile-bound wrapper was not recognized")
			}
			command, args = claudeCodeHandlerInvocation("PreToolUse", baseCommand, baseArgs, tc.open)
			if command != guard || !slices.Equal(args, claudeGuardEventArgs(launcher, hookArgs, "PreToolUse", false, tc.open)) {
				t.Fatalf("PreToolUse handler = %q %q", command, args)
			}
		})
	}
}

func TestClaudeCodeCustomLayoutRequiresAWorkingGuard(t *testing.T) {
	launcher := `C:\Custom\Hooks\defenseclaw-hook.exe`
	dir := filepath.Join(t.TempDir(), "chain")
	source := filepath.Join(t.TempDir(), windowsHookGuardBinaryName)
	oldDir, oldSource, oldProbe := claudeChainDir, claudeChainSource, claudeChainProbe
	claudeChainDir = func() string { return dir }
	claudeChainSource = func(string) string { return "" }
	claudeChainProbe = func(string, string) error { return nil }
	t.Cleanup(func() { claudeChainDir, claudeChainSource, claudeChainProbe = oldDir, oldSource, oldProbe })
	if err := ensureClaudeChain(launcher); err == nil {
		t.Fatal("custom layout without a guard was admitted")
	}
	command, args := claudeCodeWindowsHookInvocation(SetupOpts{HookExecutable: launcher}, launcher)
	if err := claudeCodeChainAdmission(SetupOpts{HookExecutable: launcher}, command, args, "windows"); err == nil {
		t.Fatal("custom layout without a chain passed setup admission")
	}
	if generated, _ := claudeCodeHandlerInvocation("UserPromptSubmit", command, args); generated != "" {
		t.Fatalf("custom layout without a chain generated %q", generated)
	}
	if _, err := os.Stat(claudeChainFilesIn(dir).record); !os.IsNotExist(err) {
		t.Fatalf("a failed guard preflight published a record: %v", err)
	}
	if err := os.WriteFile(source, []byte("MZ guard fixture"), 0o700); err != nil {
		t.Fatal(err)
	}
	claudeChainSource = func(string) string { return source }
	if err := ensureClaudeChain(launcher); err != nil {
		t.Fatal(err)
	}
	if err := claudeCodeChainAdmission(SetupOpts{HookExecutable: launcher}, command, args, "windows"); err != nil {
		t.Fatalf("working custom chain was refused: %v", err)
	}
	if err := ensureClaudeChain(`C:\Custom%Name\defenseclaw-hook.exe`); err == nil {
		t.Fatal("a launcher path cmd.exe cannot render was admitted")
	}
	generated, generatedArgs := claudeCodeHandlerInvocation("UserPromptSubmit", command, args)
	if _, _, old := claudeCodeCmdGuardParts(map[string]interface{}{"command": generated, "args": generatedArgs}); old {
		t.Fatal("the custom launcher retained the presence-only form")
	}
	if got, _, ok := claudeGuardWrapperParts(map[string]interface{}{"command": generated, "args": generatedArgs}); !ok || got != launcher {
		t.Fatalf("working custom chain was not recognized: %q %q", generated, generatedArgs)
	}
}

func TestClaudeCodeCustomLayoutUsesGatewayGuardSource(t *testing.T) {
	root := t.TempDir()
	gateway := filepath.Join(root, "bin", windowsGatewayBinaryName)
	guard := filepath.Join(filepath.Dir(gateway), windowsHookGuardBinaryName)
	launcher := filepath.Join(root, "custom", windowsHookBinaryName)
	if err := os.MkdirAll(filepath.Dir(guard), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(guard, []byte("MZ guard fixture"), 0o700); err != nil {
		t.Fatal(err)
	}
	previous := claudeChainGatewayExecutable
	claudeChainGatewayExecutable = func() (string, error) { return gateway, nil }
	t.Cleanup(func() { claudeChainGatewayExecutable = previous })
	if got := claudeChainGuardSource(launcher); got != guard {
		t.Fatalf("custom launcher guard source = %q, want %q", got, guard)
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
	guard, _ := claudeChainFor(launcher)
	files := claudeChainFilesIn(filepath.Dir(guard))
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

func TestClaudeCodeChainUpdateKeepsActivePairCoherent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "chain")
	source := filepath.Join(t.TempDir(), windowsHookGuardBinaryName)
	launcher := filepath.Join(t.TempDir(), windowsHookBinaryName)
	first, second := []byte("MZ guard one"), []byte("MZ guard two")
	if err := os.WriteFile(source, first, 0o600); err != nil {
		t.Fatal(err)
	}
	oldDir, oldSource, oldProbe := claudeChainDir, claudeChainSource, claudeChainProbe
	claudeChainDir = func() string { return dir }
	claudeChainSource = func(string) string { return source }
	claudeChainProbe = func(string, string) error { return nil }
	t.Cleanup(func() { claudeChainDir, claudeChainSource, claudeChainProbe = oldDir, oldSource, oldProbe })
	if err := ensureClaudeChain(launcher); err != nil {
		t.Fatal(err)
	}
	oldGuard, oldApproved := claudeChainFor(launcher)
	stop, done := make(chan struct{}), make(chan error, 1)
	go func() {
		for {
			select {
			case <-stop:
				done <- nil
				return
			default:
			}
			for _, path := range []string{oldGuard, oldApproved} {
				body, err := os.ReadFile(path)
				if err != nil || string(body) != string(first) {
					done <- fmt.Errorf("active pair changed at %s: %q: %v", path, body, err)
					return
				}
			}
		}
	}()
	if err := os.WriteFile(source, second, 0o600); err != nil {
		close(stop)
		<-done
		t.Fatal(err)
	}
	updateErr := ensureClaudeChain(launcher)
	close(stop)
	if monitorErr := <-done; monitorErr != nil {
		t.Fatal(monitorErr)
	}
	if updateErr != nil {
		t.Fatal(updateErr)
	}
	newGuard, newApproved := claudeChainFor(launcher)
	if newGuard == oldGuard || newApproved == oldApproved {
		t.Fatal("the update replaced an active pair")
	}
	for _, path := range []string{oldGuard, oldApproved} {
		body, err := os.ReadFile(path)
		if err != nil || string(body) != string(first) {
			t.Fatalf("active pair %s changed: %q: %v", path, body, err)
		}
	}
	for _, path := range []string{newGuard, newApproved} {
		body, err := os.ReadFile(path)
		if err != nil || string(body) != string(second) {
			t.Fatalf("new pair %s = %q: %v", path, body, err)
		}
	}
}

func TestClaudeCodeChainUpdateKeepsActiveLaunchesWorking(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "chain")
	source := filepath.Join(t.TempDir(), windowsHookGuardBinaryName)
	launcher := filepath.Join(t.TempDir(), windowsHookBinaryName)
	first := []byte("#!/bin/sh\nexit 0\n")
	if runtime.GOOS == "windows" {
		self, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		first, err = os.ReadFile(self)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(source, first, 0o700); err != nil {
		t.Fatal(err)
	}
	probeReached, releaseProbe := make(chan struct{}), make(chan struct{})
	probes := 0
	oldDir, oldSource, oldProbe := claudeChainDir, claudeChainSource, claudeChainProbe
	claudeChainDir = func() string { return dir }
	claudeChainSource = func(string) string { return source }
	claudeChainProbe = func(string, string) error {
		probes++
		if probes == 2 {
			close(probeReached)
			<-releaseProbe
		}
		return nil
	}
	t.Cleanup(func() { claudeChainDir, claudeChainSource, claudeChainProbe = oldDir, oldSource, oldProbe })
	if err := ensureClaudeChain(launcher); err != nil {
		t.Fatal(err)
	}
	activeGuard, _ := claudeChainFor(launcher)
	if runtime.GOOS != "windows" {
		if err := os.Chmod(activeGuard, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(source, append(append([]byte(nil), first...), []byte("\nupdated\n")...), 0o700); err != nil {
		t.Fatal(err)
	}
	updated := make(chan error, 1)
	go func() { updated <- ensureClaudeChain(launcher) }()
	select {
	case <-probeReached:
	case err := <-updated:
		t.Fatalf("update ended before its probe: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("update did not reach its probe")
	}
	launched := make(chan error, 1)
	firstLaunch := make(chan struct{})
	go func() {
		for i := 0; i < 21; i++ {
			cmd := exec.Command(activeGuard, "-test.run=^$")
			if output, err := cmd.CombinedOutput(); err != nil {
				launched <- fmt.Errorf("active launch %d: %v: %s", i, err, output)
				if i == 0 {
					close(firstLaunch)
				}
				return
			}
			if i == 0 {
				close(firstLaunch)
			}
		}
		launched <- nil
	}()
	select {
	case <-firstLaunch:
	case <-time.After(10 * time.Second):
		t.Fatal("active launch did not finish")
	}
	close(releaseProbe)
	if err := <-updated; err != nil {
		t.Fatal(err)
	}
	if err := <-launched; err != nil {
		t.Fatal(err)
	}
}
