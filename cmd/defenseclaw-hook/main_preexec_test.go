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

func TestR108PreExecNoArgPromptAndCursorTwin(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix managed Claude Code hook")
	}
	if os.Getenv("R108_PREEXEC_HOOK_HELPER") == "1" {
		os.Args = os.Args[:1]
		main()
		return
	}
	run := func(payload string) (int, string, string) {
		t.Helper()
		cmd := exec.Command(os.Args[0], "-test.run=^TestR108PreExecNoArgPromptAndCursorTwin$")
		cmd.Env = append(os.Environ(), "R108_PREEXEC_HOOK_HELPER=1")
		cmd.Stdin = strings.NewReader(payload)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode(), stdout.String(), stderr.String()
		}
		if err != nil {
			t.Fatal(err)
		}
		return 0, stdout.String(), stderr.String()
	}
	// With no installed runtime, a managed hook sends the structured runtime
	// response. The earlier argument refusal had no such response.
	if code, stdout, stderr := run(`{"session_id":"s","hook_event_name":"UserPromptSubmit","prompt":"hello"}`); code != 0 ||
		!strings.Contains(stdout, "enterprise_managed_runtime_descriptor_missing") || strings.Contains(stderr, "expected hook") {
		t.Fatalf("Claude Code prompt: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if code, stdout, stderr := run(cursorPreToolUse); code != 0 || stdout != "" || stderr != "" {
		t.Fatalf("Cursor import: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

func TestR108PreExecLargeCursorAndClaudeTwin(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix managed Claude Code hook")
	}
	if os.Getenv("R108_PREEXEC_LARGE_HOOK_HELPER") == "1" {
		os.Args = os.Args[:1]
		main()
		return
	}
	run := func(payload string) (int, string, string) {
		t.Helper()
		cmd := exec.Command(os.Args[0], "-test.run=^TestR108PreExecLargeCursorAndClaudeTwin$")
		cmd.Env = append(os.Environ(), "R108_PREEXEC_LARGE_HOOK_HELPER=1")
		cmd.Stdin = strings.NewReader(payload)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode(), stdout.String(), stderr.String()
		}
		if err != nil {
			t.Fatal(err)
		}
		return 0, stdout.String(), stderr.String()
	}
	content := strings.Repeat("a", 1<<20)
	for _, tc := range []struct {
		name, payload string
	}{
		{"Cursor marker first", `{"cursor_version":"3.1.0","hook_event_name":"preToolUse","tool_name":"Write","tool_input":{"content":"` + content + `"}}`},
		{"Cursor marker last", `{"hook_event_name":"preToolUse","tool_name":"Write","tool_input":{"content":"` + content + `"},"cursor_version":"3.1.0"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := run(tc.payload)
			if code != 0 || stdout != "" || stderr != "" {
				t.Fatalf("large Cursor import: exit %d, stdout %q, stderr %q", code, stdout, stderr)
			}
		})
	}
	if code, stdout, stderr := run(`{"hook_event_name":"UserPromptSubmit","prompt":"hello"}`); code != 0 ||
		!strings.Contains(stdout, "enterprise_managed_runtime_descriptor_missing") || strings.Contains(stderr, "expected hook") {
		t.Fatalf("Claude Code prompt: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if code, stdout, stderr := run(`{"cursor_version":"3.1.0","tool_input":{"content":"` + content); code != 2 ||
		stdout != "" || !strings.Contains(stderr, "expected hook") {
		t.Fatalf("incomplete Cursor import: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}
