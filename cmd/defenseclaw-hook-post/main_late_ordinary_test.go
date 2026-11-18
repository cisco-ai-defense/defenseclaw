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
// A call is ordinary only when both late-call scans of the native hook find
// it so (hookexec.LateOrdinaryBothScans): a call that the shared
// protected-reach reader refuses keeps 9 too, though the link-hop scan alone
// reads it as ordinary (rel-1-0-10 GAP-1188). An ordinary leading cd chain
// and a PermissionRequest, which both scans read, keep 12; their protected
// twins keep 9.
func TestGAP0518HookPostLateOrdinaryNoAnswerExit(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "h")
	project := filepath.Join(home, "proj")
	for _, dir := range []string{filepath.Join(home, ".ssh"), filepath.Join(project, "sub")} {
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

	postBody := func(path, body string) int {
		frame := []byte("DCPOST1\x00" + path + "\x00" + body + "\x00Content-Type\x00application/json\x00")
		return runMain([]string{"hook-post", "--api-addr", addr, "--max-time", "1", "--curl-output"},
			bytes.NewReader(frame), new(bytes.Buffer), new(bytes.Buffer))
	}
	post := func(path, tool, command string) int {
		body, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": project, "tool_name": tool,
			"tool_input": map[string]any{"command": command}})
		if err != nil {
			t.Fatal(err)
		}
		return postBody(path, string(body))
	}
	cwd, err := json.Marshal(project)
	if err != nil {
		t.Fatal(err)
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
		{"claude cd then ls", "/api/v1/claude-code/hook", "Bash", "cd sub && ls", hookexec.PerUserPostLateOrdinaryExit},
		{"codex cd to the project then go test", "/api/v1/codex/hook", "Bash", "cd " + project + " && go test ./...", hookexec.PerUserPostLateOrdinaryExit},
		{"claude cd into the SSH folder", "/api/v1/claude-code/hook", "Bash", "cd ../.ssh && cat authorized_keys", hookexec.PerUserPostNoAnswerExit},
		{"codex cd home by tilde", "/api/v1/codex/hook", "Bash", "cd ~/.ssh && cat authorized_keys", hookexec.PerUserPostNoAnswerExit},
		{"claude cd by a variable into the state folder", "/api/v1/claude-code/hook", "Bash", "cd $HOME/.defenseclaw && ls", hookexec.PerUserPostNoAnswerExit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := post(tc.path, tc.tool, tc.command); got != tc.want {
				t.Fatalf("exit %d, want %d", got, tc.want)
			}
		})
	}
	// Calls the link-hop scan alone reads as ordinary and the shared
	// protected-reach reader refuses: exit 12 at 479a1ebc12, 9 now (GAP-1188).
	for _, tc := range []struct{ name, path, body string }{
		{"codex duplicate command key, the last one plain", "/api/v1/codex/hook",
			`{"hook_event_name":"PreToolUse","cwd":` + string(cwd) + `,"tool_name":"Bash","tool_input":{"command":"cat keylink","command":"echo hi"}}`},
		{"claude camel-case tool keys", "/api/v1/claude-code/hook",
			`{"hook_event_name":"PreToolUse","cwd":` + string(cwd) + `,"toolName":"Bash","toolInput":{"command":"echo hi"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := postBody(tc.path, tc.body); got != hookexec.PerUserPostNoAnswerExit {
				t.Fatalf("exit %d, want %d", got, hookexec.PerUserPostNoAnswerExit)
			}
		})
	}
	// A PermissionRequest carries the tool and input of a PreToolUse: both
	// scans read it, so the ordinary one keeps 12 and a protected one 9.
	for _, tc := range []struct {
		name, path, command string
		want                int
	}{
		{"claude permission request", "/api/v1/claude-code/hook", "echo hi", hookexec.PerUserPostLateOrdinaryExit},
		{"codex permission request cd chain", "/api/v1/codex/hook", "cd sub && ls", hookexec.PerUserPostLateOrdinaryExit},
		{"claude permission request of a link", "/api/v1/claude-code/hook", "cat keylink", hookexec.PerUserPostNoAnswerExit},
		{"codex permission request of the keys path", "/api/v1/codex/hook", "cat ../.ssh/authorized_keys", hookexec.PerUserPostNoAnswerExit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, err := json.Marshal(map[string]any{"hook_event_name": "PermissionRequest", "cwd": project, "tool_name": "Bash",
				"tool_input": map[string]any{"command": tc.command}})
			if err != nil {
				t.Fatal(err)
			}
			if got := postBody(tc.path, string(body)); got != tc.want {
				t.Fatalf("exit %d, want %d", got, tc.want)
			}
		})
	}
}
