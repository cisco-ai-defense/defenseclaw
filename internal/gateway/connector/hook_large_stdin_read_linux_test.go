// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package connector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestShellHookReadsLargeStdinWhole pins what a shell hook does with a body
// longer than the 16 KiB it reads first (the rest is copied by head(1) and
// read from a file, not one byte per read call): a body below the cap reaches
// the gateway byte for byte, a NUL after the first block still refuses the
// call and sends nothing, and a body over the 1 MiB cap is still refused (on
// the managed render, which needs no helper binary; the per-user renders are
// pinned by TestShellHookBehaviourMatchesGolden).
func TestShellHookReadsLargeStdinWhole(t *testing.T) {
	for _, tool := range []string{"jq", "curl", "awk", "head"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is required", tool)
		}
	}
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("/bin/bash is required")
	}
	if _, err := os.Stat("/etc/defenseclaw/managed-runtime.json"); err == nil {
		t.Skip("a managed computer refuses personal hooks")
	}
	base, err := os.MkdirTemp("/tmp", "dclarge")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })

	var hook hookGoldenHook
	for _, h := range hookGoldenHooks() {
		if h.name == "codex" {
			hook = h
		}
	}
	modes := hookGoldenModes()
	payload := func(size int, nulAt int) []byte {
		command := strings.Repeat("0123456789abcdef", size/16)
		body, err := json.Marshal(map[string]any{
			"session_id": "large-session", "turn_id": "t", "hook_event_name": "PreToolUse", "tool_name": "Bash",
			"tool_input": map[string]any{"command": command}, "tool_use_id": "toolu_large", "cwd": "/tmp",
			"model": "m", "transcript_path": nil, "permission_mode": "default",
		})
		if err != nil {
			t.Fatal(err)
		}
		if nulAt > 0 {
			body = append(append(append([]byte(nil), body[:nulAt]...), 0), body[nulAt+1:]...)
		}
		return body
	}
	var next int
	run := func(t *testing.T, mode hookGoldenMode, stdin []byte, index int) hookGoldenObservation {
		t.Helper()
		obs, err := runHookGoldenCase(base, index, hookGoldenCase{
			id: "large-stdin", hook: hook, mode: mode, event: "PreToolUse", stdin: stdin, command: "ls",
			answer: hookGoldenAnswer{name: "allow", answer: hookGoldenFixed(200, `{"action":"allow"}`)},
		})
		if err != nil {
			t.Fatal(err)
		}
		return obs
	}
	type whole struct {
		mode hookGoldenMode
		size int
	}
	for _, c := range []whole{{modes[5], 20000}, {modes[5], 300000}} {
		index := next
		next++
		t.Run(fmt.Sprintf("%s/%d bytes arrive whole", c.mode.name, c.size), func(t *testing.T) {
			t.Parallel()
			stdin := payload(c.size, 0)
			obs := run(t, c.mode, stdin, index)
			if len(obs.Requests) != 1 || !bytes.Equal([]byte(obs.Requests[0].Body), stdin) {
				t.Fatalf("the gateway got %d request(s), body %d bytes; want one request with the %d bytes sent (exit %d, stderr %.200q)",
					len(obs.Requests), len(firstBody(obs)), len(stdin), obs.Exit, obs.Stderr)
			}
		})
	}
	type refused struct {
		name      string
		mode      hookGoldenMode
		stdin     []byte
		want      string
		noRequest bool
	}
	for _, c := range []refused{
		{"NUL after the first block", modes[5], payload(40000, 20000), "NUL", true},
		{"over the cap", modes[5], payload(1048576+4096, 0), "exceeded", true},
	} {
		index := next
		next++
		t.Run(c.mode.name+"/"+c.name, func(t *testing.T) {
			t.Parallel()
			obs := run(t, c.mode, c.stdin, index)
			if !strings.Contains(strings.Join(obs.Failures, "\n"), c.want) || (c.noRequest && len(obs.Requests) != 0) {
				t.Fatalf("want a logged failure naming %q (and no request: %v); got %d request(s), failures %q, exit %d",
					c.want, c.noRequest, len(obs.Requests), obs.Failures, obs.Exit)
			}
		})
	}
}

func firstBody(obs hookGoldenObservation) string {
	if len(obs.Requests) == 0 {
		return ""
	}
	return obs.Requests[0].Body
}
