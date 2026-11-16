// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// A per-user call that names a credential file after 254 existing ordinary
// files blocks before the hook deadline for both connectors (GAP-1075): just
// under the argv bound every operand is read in full, and on Windows that full
// reading passed the hook deadline, so the call failed open. The ordinary twin
// is allowed. Outside a race build each call is held to 1.5 s with 25 percent
// tolerance on Unix, and to 3 s on Windows (hosted runners are about twice as
// slow as a test host; 3 s still answers inside the 4 s hook window).
func TestCredentialOperandNearTheArgvBoundBlocksInsideTheAnswerBudget(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "proj")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	names := make([]string, 254)
	for i := range names {
		names[i] = fmt.Sprintf("g%d", i)
		if err := os.WriteFile(filepath.Join(project, names[i]), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	budget, tolerance := 1500*time.Millisecond, "1.5 s plus 25 percent"
	if runtime.GOOS == "windows" {
		budget, tolerance = 3*time.Second, "inside the 4 s hook window"
	} else {
		budget += budget / 4
	}
	rows := []struct {
		last  string
		block bool
	}{
		{"~/.netrc", true},
		{"zz-ordinary", false},
	}
	for _, row := range rows {
		command := "touch " + strings.Join(names, " ") + " " + row.last
		for _, connector := range []string{"claudecode", "codex"} {
			payload := mustJSON(t, map[string]any{"session_id": "g1075", "hook_event_name": "PreToolUse", "cwd": project,
				"permission_mode": "default", "tool_name": "Bash", "tool_use_id": "toolu_g1075",
				"tool_input": map[string]any{"command": command, "description": "touch files"}})
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = connector
			api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(payload)))
			if connector == "codex" {
				setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
			}
			recorder := httptest.NewRecorder()
			start := time.Now()
			api.handleAgentHook(connector).ServeHTTP(recorder, req)
			elapsed := time.Since(start)
			body := recorder.Body.String()
			blocked := strings.HasPrefix(body, `{"action":"block"`)
			name := fmt.Sprintf("%s %d+%s", connector, len(names), row.last)
			switch {
			case row.block && (!blocked || !strings.Contains(body, "PATH-NETRC")):
				t.Errorf("%s: want a PATH-NETRC block, got %.200s", name, body)
			case !row.block && !strings.HasPrefix(body, `{"action":"allow"`):
				t.Errorf("%s: want allow, got %.200s", name, body)
			}
			if !hookAnswerRaceBuild && elapsed > budget {
				t.Errorf("%s: answered in %s, want under %s (%s)", name, elapsed.Round(time.Millisecond), budget, tolerance)
			}
		}
	}
}
