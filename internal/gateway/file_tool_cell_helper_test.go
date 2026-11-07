// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// postFileToolCell posts one PreToolUse call of a native file tool to the
// Claude Code hook, as the per-user hook or as a managed hook peer of home,
// under the rule pack, and reports whether the verdict blocks with the
// state-write finding and the response.
func postFileToolCell(t *testing.T, home, cwd, tool string, input map[string]any, managed bool, pack string) (blocked bool, response string) {
	t.Helper()
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.RulePack = pack
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	body := mustJSON(t, map[string]any{"session_id": "s", "hook_event_name": "PreToolUse",
		"tool_name": tool, "cwd": cwd, "tool_input": input})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(body)))
	if managed {
		req.Header.Set(hookpaths.Header, hookpaths.Resolve(body))
		req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
	}
	rec := httptest.NewRecorder()
	api.handleAgentHook("claudecode").ServeHTTP(rec, req)
	got := rec.Body.String()
	return strings.HasPrefix(got, `{"action":"block"`) && strings.Contains(got, "tamper.detector_state_write"), got
}
