// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package main

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/procidentity"
)

// TestGAP1162FrozenOwnGatewayIsDecidedWithinTheShellBudget: a Codex shell
// hook gives its helper what is left of its 4 s tool-call budget (about
// 3.2 s on macOS, where bash 3.2 starts slower). A SIGSTOPped gateway of this
// account takes the connection into its accept queue and never accepts it.
// The helper waited the whole 3 s accept wait before it read who holds the
// listener, so the request deadline came first and the helper exited 1: a
// closed refusal of an ordinary ls or pwd, although the status says "no
// answer: allow with a warning unless the call may reach a protected file"
// (rel-1-0-10 GAP-1162, dc-mac). The helper now decides the queued
// connection inside its deadline: an ordinary Claude Code or Codex call and a
// prompt exit PerUserPostLateOrdinaryExit (the shell follows the outage
// mode: open with the warning in the default tiers, closed in strict), and a
// call that may reach a protected file exits PerUserPostNoAnswerExit, closed
// in every mode.
func TestGAP1162FrozenOwnGatewayIsDecidedWithinTheShellBudget(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "h")
	project := filepath.Join(home, "proj")
	for _, dir := range []string{filepath.Join(home, ".ssh"), project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(keys, []byte("# decoy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv(hookPostAccountHomeEnv, home)

	// A listener of this process that accepts nothing: what a SIGSTOPped
	// gateway looks like to the kernel. The record names this process as
	// the account's gateway.
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	dataDir := filepath.Join(root, "data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	identity, ok := procidentity.Recorded(os.Getpid())
	if !ok {
		t.Fatal("no start identity for this process")
	}
	record, err := json.Marshal(map[string]any{"pid": os.Getpid(), "executable": "/usr/local/bin/defenseclaw-gateway",
		"data_dir": dataDir, "start_time": time.Now().Unix(), "start_identity": identity})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "gateway.pid"), record, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(hookPostDataDirEnv, dataDir)
	// Below the 3 s accept wait, as the Codex shell hook's helper budget is.
	const budget = 2000 * time.Millisecond
	t.Setenv(hookPostDeadlineEnv, "2000")
	addr := listener.Addr().String()

	post := func(t *testing.T, path string, payload map[string]any) int {
		t.Helper()
		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		frame := []byte("DCPOST1\x00" + path + "\x00" + string(body) + "\x00Content-Type\x00application/json\x00")
		started := time.Now()
		code := runMain([]string{"hook-post", "--api-addr", addr, "--max-time", "3", "--curl-output"},
			bytes.NewReader(frame), new(bytes.Buffer), new(bytes.Buffer))
		if elapsed := time.Since(started); elapsed > budget+time.Second {
			t.Fatalf("the helper answered after %s, past its %s budget", elapsed, budget)
		}
		return code
	}
	tool := func(name, command string) map[string]any {
		return map[string]any{"hook_event_name": "PreToolUse", "session_id": "gap1162", "cwd": project,
			"tool_name": name, "tool_input": map[string]any{"command": command}}
	}
	for _, tc := range []struct {
		name, path string
		payload    map[string]any
		want       int
	}{
		{"codex ls", "/api/v1/codex/hook", tool("Bash", "ls"), hookexec.PerUserPostLateOrdinaryExit},
		{"codex pwd", "/api/v1/codex/hook", tool("Bash", "pwd"), hookexec.PerUserPostLateOrdinaryExit},
		{"claude code ls", "/api/v1/claude-code/hook", tool("Bash", "ls"), hookexec.PerUserPostLateOrdinaryExit},
		{"codex prompt", "/api/v1/codex/hook", map[string]any{"hook_event_name": "UserPromptSubmit", "session_id": "gap1162",
			"cwd": project, "prompt": "hello"}, hookexec.PerUserPostLateOrdinaryExit},
		// No fail-open: a call that may reach a protected file stays closed
		// in every mode, for both connectors.
		{"codex keys file", "/api/v1/codex/hook", tool("Bash", "cat ../.ssh/authorized_keys"), hookexec.PerUserPostNoAnswerExit},
		{"codex keys file by tilde", "/api/v1/codex/hook", tool("Bash", "cat ~/.ssh/authorized_keys"), hookexec.PerUserPostNoAnswerExit},
		{"claude code keys file", "/api/v1/claude-code/hook", tool("Bash", "cat "+keys), hookexec.PerUserPostNoAnswerExit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := post(t, tc.path, tc.payload)
			if tc.want == hookexec.PerUserPostNoAnswerExit &&
				(got == 0 || got == hookexec.PerUserPostLateOrdinaryExit || got == hookexec.PerUserPostOutageExit) {
				t.Fatalf("a call that may reach a protected file got exit %d, a status the shell can let through", got)
			}
			if got != tc.want {
				t.Fatalf("exit %d, want %d", got, tc.want)
			}
		})
	}
}
