// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// A per-user Windows gateway answers a Codex or Claude Code call with 5000
// ordinary operands inside the hook answer budget (4 s with the hook process
// start): the share walk of each read cost about 100 us and a call made 13
// of them an operand, which took 4.5 s of gateway time (rel-1-0-9:GAP-0943).
// The same call naming the protected keys file last is still blocked, and
// the ordinary one still allowed.
func TestWindowsLongOperandListAnswersInsideTheHookBudget(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "proj")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("USERPROFILE", home)
	t.Setenv("HOME", home)
	t.Chdir(project)
	words := make([]string, 5000)
	for i := range words {
		words[i] = fmt.Sprintf("f%d", i+1)
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	for _, tc := range []struct {
		connector, tool, field string
	}{{"codex", "exec_command", "cmd"}, {"claudecode", "Bash", "command"}} {
		for _, protected := range []bool{false, true} {
			command := "touch " + strings.Join(words, " ")
			want := "allow"
			if protected {
				command += " " + keys
				want = "block"
			}
			payload := mustJSON(t, map[string]any{"session_id": "gap0943", "hook_event_name": "PreToolUse", "cwd": project,
				"permission_mode": "default", "tool_name": tc.tool, "tool_use_id": "toolu_gap0943",
				"tool_input": map[string]any{tc.field: command}})
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = tc.connector
			api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(payload)))
			if tc.connector == "codex" {
				setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
			}
			start := time.Now()
			rec := httptest.NewRecorder()
			api.handleAgentHook(tc.connector).ServeHTTP(rec, req)
			took := time.Since(start)
			body := rec.Body.String()
			if !strings.HasPrefix(body, fmt.Sprintf(`{"action":%q`, want)) {
				t.Errorf("%s protected=%v: %.200s, want %s", tc.connector, protected, body, want)
			}
			t.Logf("%s protected=%v: %s", tc.connector, protected, took.Round(time.Millisecond))
			if took > 3*time.Second {
				t.Errorf("%s protected=%v: the gateway took %s for 5000 operands, want well inside the 4 s hook budget", tc.connector, protected, took.Round(time.Millisecond))
			}
		}
	}
}
