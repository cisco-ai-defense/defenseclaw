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
