// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// GAP-2031: a settings.json copied from another account runs that account's
// generated hook (<home>/.defenseclaw/hooks/claude-code-hook.sh). Setup must
// replace those entries and Teardown must not restore them; the user's own
// hooks stay.
func TestClaudeCode_SetupReplacesForeignDefenseClawHookEntries(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows registers the native hook launcher")
	}
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "settings.json")
	ClaudeCodeSettingsPathOverride = settingsPath
	t.Cleanup(func() { ClaudeCodeSettingsPathOverride = "" })

	foreign := filepath.ToSlash(filepath.Join(dir, "other", ".defenseclaw", "hooks", "claude-code-hook.sh"))
	own := "/usr/local/bin/my-review-hook.sh"
	handler := func(command string) map[string]interface{} {
		return map[string]interface{}{"type": "command", "command": command}
	}
	data, err := json.Marshal(map[string]interface{}{"hooks": map[string]interface{}{
		"PreToolUse": []interface{}{
			map[string]interface{}{"matcher": "*", "hooks": []interface{}{handler(foreign), handler(own)}},
		},
		"Stop": []interface{}{
			map[string]interface{}{"hooks": []interface{}{handler(foreign)}},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settingsPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	opts := SetupOpts{
		DataDir:       filepath.Join(dir, "self"),
		ProxyAddr:     "127.0.0.1:4000",
		APIAddr:       "127.0.0.1:18970",
		APIToken:      "api-token",
		OTLPPathToken: strings.Repeat("a", 64),
	}
	if err := os.MkdirAll(opts.DataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	c := NewClaudeCodeConnector()
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	after := mustReadClaudeSettingsForTest(t, settingsPath)
	if strings.Contains(after, foreign) {
		t.Fatalf("Setup kept the foreign DefenseClaw hook entries: %s", after)
	}
	if !strings.Contains(after, own) || !strings.Contains(after, filepath.ToSlash(filepath.Join(opts.DataDir, "hooks", "claude-code-hook.sh"))) {
		t.Fatalf("Setup lost the user's hook or did not register its own: %s", after)
	}

	if err := c.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	after = mustReadClaudeSettingsForTest(t, settingsPath)
	if strings.Contains(after, foreign) || !strings.Contains(after, own) {
		t.Fatalf("Teardown settings = %s, want the user's hook only", after)
	}

	for _, command := range []string{
		"/opt/other/hooks/claude-code-hook.sh",
		foreign + " --flag",
		"/home/u/.defenseclaw/hooks/other-hook.sh",
		".defenseclaw/hooks/claude-code-hook.sh",
	} {
		if hookUsesForeignDefenseClawClaudeCodeScript(handler(command)) {
			t.Errorf("claimed %q as a DefenseClaw hook", command)
		}
	}
}

// GAP-0907: after the hook script path in settings.json is edited, the
// self-heal Setup replaces the edited handlers instead of adding a second
// hook set next to them.
func TestClaudeCode_SetupReplacesEditedHookPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows registers the native hook launcher")
	}
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "settings.json")
	ClaudeCodeSettingsPathOverride = settingsPath
	t.Cleanup(func() { ClaudeCodeSettingsPathOverride = "" })
	opts := SetupOpts{
		DataDir:       filepath.Join(dir, ".defenseclaw"),
		ProxyAddr:     "127.0.0.1:4000",
		APIAddr:       "127.0.0.1:18970",
		APIToken:      "api-token",
		OTLPPathToken: strings.Repeat("a", 64),
	}
	if err := os.MkdirAll(opts.DataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	c := NewClaudeCodeConnector()
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	installed := mustReadClaudeSettingsForTest(t, settingsPath)
	edited := strings.ReplaceAll(installed, "/.defenseclaw/hooks/", "/.defenseclaw/xhooks/")
	if edited == installed {
		t.Fatal("fixture did not edit the hook path")
	}
	if err := os.WriteFile(settingsPath, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("repair Setup: %v", err)
	}
	repaired := mustReadClaudeSettingsForTest(t, settingsPath)
	if strings.Contains(repaired, "/xhooks/") {
		t.Fatalf("repair kept the edited hook entries: %s", repaired)
	}
	script := filepath.ToSlash(filepath.Join(opts.DataDir, "hooks", "claude-code-hook.sh"))
	if got, want := strings.Count(repaired, script), strings.Count(installed, script); got != want {
		t.Fatalf("repaired settings name the hook script %d times, want %d (one hook set)", got, want)
	}
}

func mustReadClaudeSettingsForTest(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// GAP-0368: a malformed settings.json refuses Setup before anything changes,
// naming the file and position, so the gateway keeps the earlier hooks and
// starts the other connectors. GAP-0367: if a fail-closed connector is rolled
// back after a failed start, its cached hook path keeps blocking with the
// cause instead of exiting 0.
func TestClaudeCode_MalformedSettingsRefusedAndRollbackKeepsBlocking(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows registers the native hook launcher")
	}
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "settings.json")
	ClaudeCodeSettingsPathOverride = settingsPath
	t.Cleanup(func() { ClaudeCodeSettingsPathOverride = "" })
	if err := os.WriteFile(settingsPath, []byte("{\"model\": \"x\"}\n{ broken\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := SetupOpts{
		DataDir:       filepath.Join(dir, "self"),
		APIAddr:       "127.0.0.1:18970",
		APIToken:      "api-token",
		OTLPPathToken: strings.Repeat("a", 64),
		HookFailMode:  "closed",
	}
	if err := os.MkdirAll(opts.DataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	c := NewClaudeCodeConnector()
	err := c.Setup(context.Background(), opts)
	if !errors.Is(err, ErrSetupRefusedUnchanged) || !strings.Contains(err.Error(), settingsPath) || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("Setup error = %v, want an unchanged refusal naming %s and line 2", err, settingsPath)
	}
	hookScript := filepath.Join(opts.DataDir, "hooks", "claude-code-hook.sh")
	if _, statErr := os.Stat(hookScript); !os.IsNotExist(statErr) {
		t.Fatalf("Setup wrote %s before refusing: %v", hookScript, statErr)
	}

	opts.FailedSetupFailClosed = HookFailClosed(opts, c)
	if !opts.FailedSetupFailClosed {
		t.Fatal("a closed Claude Code connector is not reported fail-closed")
	}
	if err := writeDisabledHookTombstone(opts, "claude-code-hook.sh", "Claude Code"); err != nil {
		t.Fatal(err)
	}
	out, runErr := exec.Command(hookScript).CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(runErr, &exitErr) || exitErr.ExitCode() != 2 || !strings.Contains(string(out), "defenseclaw-gateway start") {
		t.Fatalf("placeholder: err=%v out=%q, want exit 2 naming defenseclaw-gateway start", runErr, out)
	}
}

// GAP-0542: after an account rename or a home move the registered hook path
// is gone and the shell exits 127, which Claude Code treats as non-blocking,
// so tool calls ran unguarded. The per-user command blocks (exit 2) with one
// sentence when its script cannot start, passes the script exit through
// otherwise, and an old-home guarded entry is still claimed for repair.
func TestClaudeCode_PerUserHookCommandFailsClosedWhenScriptMissing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows registers the native hook launcher")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "Alice Smith", ".defenseclaw", "hooks", "claude-code-hook.sh")
	command, _ := claudeCodeHookInvocation(SetupOpts{DataDir: filepath.Join(dir, ".defenseclaw")}, script)
	if !strings.HasPrefix(command, shellSingleQuote(script)+" ") {
		t.Fatalf("command %q does not start with the quoted hook script", command)
	}
	run := func() (int, string) {
		cmd := exec.Command("/bin/sh", "-c", command)
		var stderr strings.Builder
		cmd.Stderr = &stderr
		err := cmd.Run()
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode(), stderr.String()
		}
		if err != nil {
			t.Fatal(err)
		}
		return 0, stderr.String()
	}
	// GAP-1079: after rm -rf ~/.defenseclaw the installer alone does not
	// bring the hooks back; the sentence names the whole repair.
	if code, stderr := run(); code != 2 ||
		!strings.Contains(stderr, "Run the DefenseClaw installer, then defenseclaw quickstart") {
		t.Fatalf("missing script: exit %d stderr %q, want a block (2) that names the repair", code, stderr)
	}
	if err := os.MkdirAll(filepath.Dir(script), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, want := range []int{0, 2, 3} {
		if err := os.WriteFile(script, []byte(fmt.Sprintf("#!/bin/sh\nexit %d\n", want)), 0o700); err != nil {
			t.Fatal(err)
		}
		if code, stderr := run(); code != want || stderr != "" {
			t.Fatalf("script exit %d: command exit %d stderr %q", want, code, stderr)
		}
	}
	oldHome, _ := claudeCodeHookInvocation(SetupOpts{}, "/home/old/.defenseclaw/hooks/claude-code-hook.sh")
	if !hookUsesForeignDefenseClawClaudeCodeScript(map[string]interface{}{"command": oldHome}) {
		t.Fatalf("an old-home guarded entry %q is not claimed for repair", oldHome)
	}
}

// GAP-1091: Claude Code treats a hook it cannot spawn as a non-blocking error,
// so a quarantined defenseclaw-hook.exe let every call through. Per-user
// Windows Setup runs the launcher through cmd.exe, which blocks with exit 2
// when it is missing; ownership and contract checks see the exec form it runs.
func TestClaudeCodeWindowsLauncherGuardFailsClosedAndReadsAsExecForm(t *testing.T) {
	launcher := `C:\Users\Ana Lima\.local\bin\defenseclaw-hook.exe`
	command, args := claudeCodeWindowsHookInvocation(SetupOpts{}, launcher)
	if !strings.EqualFold(filepath.Base(strings.ReplaceAll(command, `\`, "/")), "cmd.exe") {
		t.Fatalf("per-user command = %q, want the system cmd.exe", command)
	}
	tail := strings.Join(args[len(args)-6:], " ")
	if args[4] != launcher || args[6] != launcher || tail != "1>&2 & exit /b 2 )" {
		t.Fatalf("guard argv = %q", args)
	}
	view, ok := claudeCodeExecView(map[string]interface{}{"type": "command", "command": command, "args": args}).(map[string]interface{})
	if !ok || view["command"] != launcher || !hasClaudeCodeNativeExecArgs(view) {
		t.Fatalf("guard view = %#v, want the exec form of %s", view, launcher)
	}
	if got := claudeCodeRecordedHookCommand(command, args); got != launcher {
		t.Fatalf("recorded command = %q, want the launcher", got)
	}

	edited := append([]string(nil), args...)
	edited[len(edited)-2] = "0"
	hook := map[string]interface{}{"type": "command", "command": command, "args": edited}
	if got := claudeCodeExecView(hook).(map[string]interface{}); got["command"] != command {
		t.Fatal("an edited guard that exits 0 was read as the generated one")
	}
	if managed, _ := claudeCodeWindowsHookInvocation(SetupOpts{ManagedEnterprise: true}, launcher); managed != launcher {
		t.Fatalf("managed command = %q, want the exec form its guardian restores", managed)
	}
	if plain, _ := claudeCodeWindowsHookInvocation(SetupOpts{}, `C:\Users\a%b\x.exe`); plain != `C:\Users\a%b\x.exe` {
		t.Fatalf("a launcher path cmd.exe would expand kept the guard: %q", plain)
	}
}
