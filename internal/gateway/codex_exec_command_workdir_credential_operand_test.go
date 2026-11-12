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

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// A per-user Codex exec_command call (tool_input cmd and workdir) that touches
// 254 or 255 operands ending in a credential file is blocked on its credential
// rule, as the Bash shape is, at handler entry (GAP-1076). The gateway places
// the workdir (cleaned and resolved, as the request cwd is); left in the
// proved arguments, its text was a second working directory, and on a Windows
// host, where the two spellings differ, the parse was ambiguous and the rule
// only alerted, while 300 operands, judged on the reduced reading, blocked.
// The ordinary twin is allowed.
func TestCodexExecCommandWithAWorkdirKeepsTheCredentialVerdictAtTheArgvBound(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "proj")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	names := make([]string, 255)
	for i := range names {
		names[i] = fmt.Sprintf("r109g%d", i)
		if err := os.WriteFile(filepath.Join(project, names[i]), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rows := []struct {
		operands int
		last     string
		block    bool
	}{
		{254, "~/.netrc", true},
		{255, "~/.netrc", true},
		{255, "zz-ordinary", false},
	}
	for _, row := range rows {
		command := "touch " + strings.Join(names[:row.operands-1], " ") + " " + row.last
		payload := mustJSON(t, map[string]any{"session_id": "g1076", "hook_event_name": "PreToolUse", "cwd": project,
			"permission_mode": "default", "tool_name": "exec_command", "tool_use_id": "call_g1076", "model": "x",
			"turn_id": "g1076", "tool_input": map[string]any{"cmd": command, "workdir": project,
				"yield_time_ms": 10000, "max_output_tokens": 2000}})
		cfg := &config.Config{}
		cfg.Guardrail.Mode = "action"
		cfg.Guardrail.Connector = "codex"
		api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(payload)))
		setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
		recorder := httptest.NewRecorder()
		api.handleAgentHook("codex").ServeHTTP(recorder, req)
		body := recorder.Body.String()
		name := fmt.Sprintf("exec_command %d operands, last %s", row.operands, row.last)
		switch {
		case row.block && (!strings.HasPrefix(body, `{"action":"block"`) || !strings.Contains(body, "PATH-NETRC")):
			t.Errorf("%s: want a PATH-NETRC block, got %.400s", name, body)
		case !row.block && !strings.HasPrefix(body, `{"action":"allow"`):
			t.Errorf("%s: want allow, got %.400s", name, body)
		}
	}
}
