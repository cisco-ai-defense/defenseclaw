// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// TestGAP0518HookPostLateOrdinaryNoAnswerExit: a call its verified gateway
// took and did not answer by the deadline exits 12 (the shell follows the
// outage mode) when it plainly names nothing protected, and keeps 9 (closed
// in every mode) when it names the keys file or a link or hard link to it, in
// a short or a 2000-operand list, or is not a Claude Code or Codex tool call.
func TestGAP0518HookPostLateOrdinaryNoAnswerExit(t *testing.T) {
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
	if err := os.Symlink(keys, filepath.Join(project, "keylink")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(keys, filepath.Join(project, "hardlink")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(keys, filepath.Join(project, "-keylink")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv(hookPostAccountHomeEnv, home)
	words := make([]string, 2000)
	for i := range words {
		words[i] = "lo" + strings.Repeat("x", i%5) + "." + string(rune('a'+i%26)) + itoa(i)
	}
	long := "touch " + strings.Join(words, " ")

	done := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-done:
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	defer close(done)
	t.Setenv(hookPostDeadlineEnv, "700")
	t.Setenv(hookPostDataDirEnv, t.TempDir())
	addr := strings.TrimPrefix(server.URL, "http://")

	post := func(path, tool, command string) int {
		body, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": project, "tool_name": tool,
			"tool_input": map[string]any{"command": command}})
		if err != nil {
			t.Fatal(err)
		}
		frame := []byte("DCPOST1\x00" + path + "\x00" + string(body) + "\x00Content-Type\x00application/json\x00")
		return runMain([]string{"hook-post", "--api-addr", addr, "--max-time", "1", "--curl-output"},
			bytes.NewReader(frame), new(bytes.Buffer), new(bytes.Buffer))
	}
	for _, tc := range []struct {
		name, path, tool, command string
		want                      int
	}{
		{"claude echo", "/api/v1/claude-code/hook", "Bash", "echo hi", hookexec.PerUserPostLateOrdinaryExit},
		{"codex echo", "/api/v1/codex/hook", "Bash", "echo hi", hookexec.PerUserPostLateOrdinaryExit},
		{"claude 2000 operands", "/api/v1/claude-code/hook", "Bash", long, hookexec.PerUserPostLateOrdinaryExit},
		{"claude ordinary words", "/api/v1/claude-code/hook", "Bash", "echo claw defense", hookexec.PerUserPostLateOrdinaryExit},
		{"claude attached output option", "/api/v1/claude-code/hook", "Bash", "curl -okeylink http://example.invalid/x", hookexec.PerUserPostNoAnswerExit},
		{"codex redirect to a dash-named link", "/api/v1/codex/hook", "Bash", "echo x > -keylink", hookexec.PerUserPostNoAnswerExit},
		{"claude link", "/api/v1/claude-code/hook", "Bash", "cat keylink", hookexec.PerUserPostNoAnswerExit},
		{"codex hard link", "/api/v1/codex/hook", "Bash", "cat hardlink", hookexec.PerUserPostNoAnswerExit},
		{"claude 2000 operands, link last", "/api/v1/claude-code/hook", "Bash", long + " keylink", hookexec.PerUserPostNoAnswerExit},
		{"claude keys path", "/api/v1/claude-code/hook", "Bash", "cat ../.ssh/authorized_keys", hookexec.PerUserPostNoAnswerExit},
		{"claude echo of a state folder word", "/api/v1/claude-code/hook", "Bash", "echo openclaw", hookexec.PerUserPostLateOrdinaryExit},
		{"codex sed write command to the link", "/api/v1/codex/hook", "Bash", `sed -n -e "w keylink" plain.txt`, hookexec.PerUserPostNoAnswerExit},
		{"other connector", "/api/v1/cursor/hook", "Bash", "echo hi", hookexec.PerUserPostNoAnswerExit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := post(tc.path, tc.tool, tc.command); got != tc.want {
				t.Fatalf("exit %d, want %d", got, tc.want)
			}
		})
	}
}
