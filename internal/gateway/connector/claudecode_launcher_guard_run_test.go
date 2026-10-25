// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func guardStdin(t *testing.T, payload string) *os.File {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	go func() {
		_, _ = writer.WriteString(payload)
		_ = writer.Close()
	}()
	return reader
}

// The one-line install's PreToolUse handler starts defenseclaw-gateway.exe as
// the launcher guard. A launcher removed in the middle of a turn must block
// the tool call with exit 2 (GAP-1011 round 2), and Cursor's argument-free
// start of the imported handler must get no answer (GAP-1011).
func TestGatewayPreToolGuardBlocksAMissingLauncherAndAnswersCursorWithNothing(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "gone", "defenseclaw-hook.exe")
	guardArgv := []string{ClaudeCodeLauncherGuardSubcommand, missing, "hook", "--connector", "claudecode"}
	cursor := `{"cursor_version":"2.4.21","hook_event_name":"preToolUse","tool_name":"Shell"}`
	claude := `{"hook_event_name":"PreToolUse","tool_name":"Bash"}`
	for _, tc := range []struct {
		name, goos string
		args       []string
		stdin      string
		code       int
		handled    bool
		stderr     string
	}{
		{"missing launcher blocks", "windows", guardArgv, claude, 2, true, ClaudeCodeLauncherMissingMessage + "\n"},
		{"missing launcher blocks on any OS", "linux", guardArgv, claude, 2, true, ClaudeCodeLauncherMissingMessage + "\n"},
		{"cursor start without args", "windows", nil, cursor, 0, true, ""},
		{"cursor start off Windows", "linux", nil, cursor, 0, false, ""},
		{"claude event without args", "windows", nil, claude, 0, false, ""},
		{"not json without args", "windows", nil, "start", 0, false, ""},
		{"gateway subcommand", "windows", []string{"start"}, cursor, 0, false, ""},
		{"edited guard argv", "windows", append(append([]string(nil), guardArgv...), "--fail-open"), claude, 0, false, ""},
		{"relative launcher", "windows", []string{ClaudeCodeLauncherGuardSubcommand, "defenseclaw-hook.exe", "hook", "--connector", "claudecode"}, claude, 0, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code, handled := ClaudeCodeGatewayPreToolGuard(tc.goos, tc.args, guardStdin(t, tc.stdin), &stdout, &stderr)
			if code != tc.code || handled != tc.handled {
				t.Fatalf("= (%d, %v), want (%d, %v); stderr %q", code, handled, tc.code, tc.handled, stderr.String())
			}
			if stdout.Len() != 0 || stderr.String() != tc.stderr {
				t.Fatalf("stdout %q stderr %q, want no answer and stderr %q", stdout.String(), stderr.String(), tc.stderr)
			}
		})
	}
}

// A launcher that runs keeps its own exit code, stdout and stdin.
func TestGatewayPreToolGuardPassesTheLauncherThrough(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("cmd/defenseclaw-hook's launcher guard test runs a real launcher on Windows")
	}
	launcher := filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
	if err := os.WriteFile(launcher, []byte("#!/bin/sh\nprintf '%s|' \"$@\"\ncat\nexit 7\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	args := []string{ClaudeCodeLauncherGuardSubcommand, launcher, "hook", "--connector", "claudecode"}
	code, handled := ClaudeCodeGatewayPreToolGuard("windows", args, guardStdin(t, "{}"), &stdout, &stderr)
	if code != 7 || !handled || stdout.String() != "hook|--connector|claudecode|{}" || stderr.Len() != 0 {
		t.Fatalf("= (%d, %v) stdout %q stderr %q", code, handled, stdout.String(), stderr.String())
	}
}
