// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// GAP-0323: a per-user gateway that accepts a tool call and stalls in the
// middle of its answer (200, Content-Length 200, 18 bytes, then nothing)
// fails a closed Claude Code or Codex shell hook within the native hook's
// bounded answer budget. The call is blocked.
func TestClosedShellHookCutsAStalledAnswerAtTheToolCallBudget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native Windows uses the authenticated hook executor")
	}
	release := make(chan struct{})
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", "200")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"action":"allow",`))
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		select {
		case <-release:
		case <-time.After(15 * time.Second):
		}
	}))
	t.Cleanup(func() {
		close(release)
		server.Close()
	})
	addr := strings.TrimPrefix(server.URL, "http://")
	for _, agent := range []struct {
		conn    Connector
		script  string
		args    []string
		payload string
	}{
		{NewClaudeCodeConnector(), "claude-code-hook.sh", nil, `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo ok"}}`},
		// Spaced JSON keeps the bound: the event comes from the parsed payload.
		{NewClaudeCodeConnector(), "claude-code-hook.sh", nil, `{"hook_event_name" : "PreToolUse", "tool_name" : "Bash", "tool_input" : {"command" : "echo ok"}}`},
		{NewCodexConnector(), "codex-hook.sh", []string{"--event", "PreToolUse", "--hook-contract", "codex-hooks-v4"}, `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo ok"}}`},
	} {
		t.Run(agent.conn.Name(), func(t *testing.T) {
			requests.Store(0)
			home := t.TempDir()
			installNativeGatewayForHookTest(t, home)
			dataDir := filepath.Join(home, ".defenseclaw")
			hookDir := filepath.Join(dataDir, "hooks")
			opts := SetupOpts{DataDir: dataDir, APIAddr: addr, APIToken: "scoped-test-token", HookFailMode: "closed"}
			if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, agent.conn); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", append([]string{filepath.Join(hookDir, agent.script)}, agent.args...)...)
			cmd.Stdin = strings.NewReader(agent.payload)
			cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "DEFENSECLAW_GATEWAY_AUTOSTART=0"}
			started := time.Now()
			out, err := cmd.CombinedOutput()
			elapsed := time.Since(started)
			blocked := err != nil || strings.Contains(string(out), `"decision":"block"`) ||
				strings.Contains(string(out), `"permissionDecision":"deny"`)
			if !blocked {
				t.Fatalf("a stalled answer did not block the call: err=%v output=%s", err, out)
			}
			if requests.Load() == 0 || elapsed > 6*time.Second {
				t.Fatalf("a stalled answer held the call %s (%d requests), want a delivered request and a closed answer within 6 s; output=%s",
					elapsed, requests.Load(), out)
			}
		})
	}
}
