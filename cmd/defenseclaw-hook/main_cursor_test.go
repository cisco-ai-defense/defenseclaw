// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// cursorPreToolUse is the shape of the event Cursor Agent sends a Claude Code
// hook it imported from ~/.claude/settings.json (GAP-1011).
const cursorPreToolUse = `{"conversation_id":"c1","generation_id":"g1","model":"auto",` +
	`"tool_name":"Shell","tool_input":{"command":"echo ok","cwd":"C:\\Users\\u\\proj"},` +
	`"hook_event_name":"preToolUse","cursor_version":"2026.10.01-e373342",` +
	`"workspace_roots":["/c:/Users/u/proj"],"user_email":null}`

func pipeWith(t *testing.T, payload string) *os.File {
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

func TestNonHookInvocationAnswersNothingForACursorImportedClaudeHook(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		payload string
		want    int
	}{
		{name: "cursor event, no arguments", payload: cursorPreToolUse, want: 0},
		{name: "cursor version first", payload: `{"cursor_version":"3.1.0","hook_event_name":"preToolUse","tool_input":{"a":[1,{"b":2}]}}`, want: 0},
		{name: "cursor event with an argument", args: []string{"start"}, payload: cursorPreToolUse, want: 2},
		{name: "claude code event", payload: `{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo ok"}}`, want: 2},
		{name: "empty cursor version", payload: `{"cursor_version":"","hook_event_name":"preToolUse"}`, want: 2},
		{name: "nested cursor version only", payload: `{"tool_input":{"cursor_version":"3.1.0"}}`, want: 2},
		{name: "cursor version not a string", payload: `{"cursor_version":3}`, want: 2},
		{name: "truncated object", payload: `{"cursor_version":"3.1.0","tool_input":{`, want: 2},
		{name: "not an object", payload: `["cursor_version","3.1.0"]`, want: 2},
		{name: "empty stdin", payload: ``, want: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stderr bytes.Buffer
			got := nonHookInvocationExit(tc.args, pipeWith(t, tc.payload), &stderr)
			if got != tc.want {
				t.Fatalf("exit = %d, want %d (stderr %q)", got, tc.want, stderr.String())
			}
			if got == 0 && stderr.Len() != 0 {
				t.Fatalf("a Cursor import wrote stderr %q", stderr.String())
			}
			if got == 2 && !strings.Contains(stderr.String(), "expected hook") {
				t.Fatalf("refusal stderr = %q", stderr.String())
			}
		})
	}
	if got := nonHookInvocationExit(nil, nil, &bytes.Buffer{}); got != 2 {
		t.Fatalf("no stdin: exit = %d, want 2", got)
	}
}

// The built launcher, started the way Cursor starts an imported Claude Code
// handler (no arguments, the event on stdin), exits 0 with no output; before,
// it exited 2 and Cursor blocked the tool call (GAP-1011).
func TestLauncherStartedWithoutArgumentsByCursorGivesNoAnswer(t *testing.T) {
	if runtime.GOOS == "windows" {
		// A Windows test host has no per-user hook runtime, which main
		// answers as an intentional no-op before this check; the function
		// test above covers Windows.
		t.Skip("no per-user hook runtime on the test host")
	}
	if os.Getenv("DEFENSECLAW_HOOK_MAIN_UNDER_TEST") == "1" {
		os.Args = os.Args[:1]
		main()
		return
	}
	run := func(payload string) (int, string, string) {
		cmd := exec.Command(os.Args[0], "-test.run=^TestLauncherStartedWithoutArgumentsByCursorGivesNoAnswer$")
		cmd.Env = append(os.Environ(), "DEFENSECLAW_HOOK_MAIN_UNDER_TEST=1")
		cmd.Stdin = strings.NewReader(payload)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		code := 0
		if exitErr, ok := err.(*exec.ExitError); ok {
			code = exitErr.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		return code, stdout.String(), stderr.String()
	}
	if code, stdout, stderr := run(cursorPreToolUse); code != 0 || stdout != "" {
		t.Fatalf("Cursor import: exit %d, stdout %q, stderr %q; want exit 0 and no output", code, stdout, stderr)
	}
	if code, _, stderr := run(`{"hook_event_name":"PreToolUse"}`); code != 2 || !strings.Contains(stderr, "expected hook") {
		t.Fatalf("non-Cursor start without a subcommand: exit %d, stderr %q; want the exit-2 refusal", code, stderr)
	}
}
