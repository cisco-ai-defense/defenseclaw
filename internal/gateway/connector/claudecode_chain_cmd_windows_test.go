// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookguard"
)

// The wrapper is a cmd.exe command line, so only cmd.exe can say what it does.
// cmd.exe reads everything after an unparenthesized if on the same line as the
// body of that if: the first form of the wrapper ("if not exist guard ( .. ) &
// guard ...") exited 0 without starting the guard whenever the guard existed,
// so no managed Claude Code event reached the hook and nothing was audited,
// while every comparison of the argument list with its own generator passed.
// These tests run the registered command and arguments themselves with a copy
// of this test binary as the guard.
type cmdWrapperRun struct {
	code           int
	stdout, stderr string
}

func runRegisteredWrapper(t *testing.T, command string, args []string, status string) cmdWrapperRun {
	t.Helper()
	cmd := exec.Command(command, args...)
	cmd.Env = append(os.Environ(), fakeGuardStatusEnv+"="+status)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	_ = cmd.Run()
	if cmd.ProcessState == nil {
		t.Fatalf("the wrapper did not start: %s %q", command, args)
	}
	return cmdWrapperRun{cmd.ProcessState.ExitCode(), stdout.String(), stderr.String()}
}

// cmdWrapperFolder is an install folder with a space in its name that holds the
// guard (a copy of the running test binary) and its approved copy.
func cmdWrapperFolder(t *testing.T) (guard, approved, launcher string) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "Defense Claw", "bin")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	guard = filepath.Join(dir, windowsHookGuardBinaryName)
	approved = filepath.Join(dir, claudeChainApprovedName)
	for _, path := range []string{guard, approved} {
		if err := os.WriteFile(path, body, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return guard, approved, filepath.Join(dir, windowsHookBinaryName)
}

func TestManagedClaudeCodeWrapperRunsUnderCmdExe(t *testing.T) {
	guard, _, launcher := cmdWrapperFolder(t)
	hookArgs := []string{"hook", "--connector", "claudecode", "--enterprise-managed"}
	base := hookguard.WrappedExitBase
	for _, tc := range []struct {
		event, status string
		wantCode      int
		guardRuns     bool
	}{
		{"PreToolUse", "0", 0, true},
		{"PreToolUse", "2", 2, true},
		{"PreToolUse", fmt.Sprint(base + 1), 1, true},
		{"PreToolUse", fmt.Sprint(base + 5), 5, true},
		{"PreToolUse", fmt.Sprint(2*base - 1), 65535, true},
		{"PreToolUse", "1", 2, true},
		{"PreToolUse", "9009", 2, true},
		{"PreToolUse", "-1", 2, true},
		{"Stop", "-1", 1, true},
		{"PreToolUse", fmt.Sprint(base), 2, true},
		{"PreToolUse", fmt.Sprint(2 * base), 2, true},
		{"UserPromptSubmit", "0", 0, true},
		{"UserPromptSubmit", "3", 2, true},
		{"Stop", "0", 0, true},
		{"Stop", "2", 2, true},
		{"Stop", fmt.Sprint(base + 1), 1, true},
		{"Stop", "3", 1, true},
	} {
		command, args := claudeManagedGuardWrapperInvocation(tc.event, launcher, hookArgs)
		got := runRegisteredWrapper(t, command, args, tc.status)
		if got.code != tc.wantCode || strings.Contains(got.stdout, "guard-ran") != tc.guardRuns {
			t.Errorf("%s, guard status %s: exit %d, guard ran %t; want exit %d, guard ran %t (stdout %q, stderr %q)",
				tc.event, tc.status, got.code, strings.Contains(got.stdout, "guard-ran"), tc.wantCode, tc.guardRuns, got.stdout, got.stderr)
		}
	}
	// A guard that is there but is not a program answers by the event's code
	// too: cmd.exe cannot start it, and the exit must not be read as success.
	if err := os.WriteFile(guard, []byte("not a program"), 0o700); err != nil {
		t.Fatal(err)
	}
	for event, want := range map[string]int{"PreToolUse": 2, "UserPromptSubmit": 2, "Stop": 1} {
		command, args := claudeManagedGuardWrapperInvocation(event, launcher, hookArgs)
		if got := runRegisteredWrapper(t, command, args, "0"); got.code != want {
			t.Errorf("%s, guard is not a program: exit %d (want %d), stdout %q, stderr %q", event, got.code, want, got.stdout, got.stderr)
		}
	}
	// A guard that is not there answers by the event's documented code and
	// names the guard and the repair.
	if err := os.Remove(guard); err != nil {
		t.Fatal(err)
	}
	for event, want := range map[string]int{"PreToolUse": 2, "UserPromptSubmit": 2, "PermissionRequest": 2, "PostToolUse": 2, "Stop": 1, "SessionEnd": 1} {
		command, args := claudeManagedGuardWrapperInvocation(event, launcher, hookArgs)
		got := runRegisteredWrapper(t, command, args, "0")
		if got.code != want || strings.Contains(got.stdout, "guard-ran") ||
			!strings.Contains(got.stderr, windowsHookGuardBinaryName) || !strings.Contains(got.stderr, "/repair") {
			t.Errorf("%s, guard missing: exit %d (want %d), stdout %q, stderr %q", event, got.code, want, got.stdout, got.stderr)
		}
	}
}

func TestPerUserClaudeCodeChainWrapperRunsUnderCmdExe(t *testing.T) {
	guard, approved, launcher := cmdWrapperFolder(t)
	hookArgs := []string{"hook", "--connector", "claudecode"}
	wrapper := func(event string, open bool) (string, []string) {
		return claudeCodeWindowsCommandProcessor(), claudeGuardWrapperArgs(guard, approved, launcher, event, hookArgs, open)
	}
	base := hookguard.WrappedExitBase
	for _, tc := range []struct {
		event, status string
		open          bool
		wantCode      int
	}{
		{"UserPromptSubmit", "0", false, 0},
		{"UserPromptSubmit", "2", false, 2},
		{"UserPromptSubmit", fmt.Sprint(base + 1), false, 1},
		{"UserPromptSubmit", "1", false, 2},
		{"UserPromptSubmit", "1", true, 1},
		{"Stop", "0", false, 0},
		{"Stop", "1", false, 1},
	} {
		command, args := wrapper(tc.event, tc.open)
		got := runRegisteredWrapper(t, command, args, tc.status)
		if got.code != tc.wantCode || (tc.status == "0" || tc.status == "2" || tc.status == fmt.Sprint(base+1)) && !strings.Contains(got.stdout, "guard-ran") {
			t.Errorf("%s (open %t), guard status %s: exit %d, stdout %q, stderr %q; want exit %d", tc.event, tc.open, tc.status, got.code, got.stdout, got.stderr, tc.wantCode)
		}
	}
	// A guard that differs from the approved copy is not started. The changed
	// file is the same program with a byte appended, so it would run and print
	// if the compare let it through.
	body, err := os.ReadFile(approved)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(guard, append(body, 0), 0o700); err != nil {
		t.Fatal(err)
	}
	command, args := wrapper("UserPromptSubmit", false)
	if got := runRegisteredWrapper(t, command, args, "0"); got.code != 2 || strings.Contains(got.stdout, "guard-ran") {
		t.Errorf("changed guard: exit %d, stdout %q, stderr %q; want exit 2 and no guard start", got.code, got.stdout, got.stderr)
	}
	// A guard that is gone answers by the event's code.
	if err := os.Remove(guard); err != nil {
		t.Fatal(err)
	}
	command, args = wrapper("Stop", false)
	if got := runRegisteredWrapper(t, command, args, "0"); got.code != 1 || strings.Contains(got.stdout, "guard-ran") {
		t.Errorf("missing guard on Stop: exit %d, stdout %q; want exit 1", got.code, got.stdout)
	}
}
