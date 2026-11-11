// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

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

// A per-user call that names a credential file after 199, 254 or 299
// existing ordinary files blocks inside the answer budget for both
// connectors (GAP-1075): just under the argv bound every operand is read in
// full, and on Windows that full reading passed the hook deadline, so the
// call failed open. The ordinary twin at the bound is allowed. Outside a race
// build each call is held to 1.5 s with 25 percent tolerance; this runs on
// every OS job, the Windows one included.
func TestCredentialOperandNearTheArgvBoundBlocksInsideTheAnswerBudget(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "proj")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	names := make([]string, 299)
	for i := range names {
		names[i] = fmt.Sprintf("g%d", i)
		if err := os.WriteFile(filepath.Join(project, names[i]), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	const budget = 1500 * time.Millisecond
	rows := []struct {
		before int
		last   string
		block  bool
	}{
		{199, "~/.netrc", true},
		{254, "~/.netrc", true},
		{299, "~/.netrc", true},
		{254, "zz-ordinary", false},
	}
	for _, row := range rows {
		command := "touch " + strings.Join(names[:row.before], " ") + " " + row.last
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
			name := fmt.Sprintf("%s %d+%s", connector, row.before, row.last)
			switch {
			case row.block && (!blocked || !strings.Contains(body, "PATH-NETRC")):
				t.Errorf("%s: want a PATH-NETRC block, got %.200s", name, body)
			case !row.block && !strings.HasPrefix(body, `{"action":"allow"`):
				t.Errorf("%s: want allow, got %.200s", name, body)
			}
			if !hookAnswerRaceBuild && elapsed > budget+budget/4 {
				t.Errorf("%s: answered in %s, want under %s (25 percent tolerance)", name, elapsed.Round(time.Millisecond), budget)
			}
		}
	}
}
