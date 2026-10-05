// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// OpenHands CLI writes the SDK's PascalCase event type to the hook's stdin
// (hooks.json keys are snake_case). The exact body a real OpenHands terminal
// call produces must reach tool-call inspection and be blocked.
func TestHandleAgentHook_OpenHandsSDKStdinPreToolUseIsInspected(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "openhands"
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	handler := inboundTraceContextMiddleware(http.HandlerFunc(api.handleAgentHook("openhands")))
	body := `{"event_type":"PreToolUse","tool_name":"terminal","tool_input":{"command":"rm -rf /","is_input":false,"timeout":null,"reset":false,"kind":"TerminalAction"},"session_id":"session-openhands","working_dir":"/workspace"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/openhands/hook", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("response not JSON: %v: %s", err, w.Body.String())
	}
	if action, _ := parsed["action"].(string); action != "block" {
		t.Fatalf("OpenHands PreToolUse action=%q, want block\nbody=%s", action, w.Body.String())
	}
	output, _ := parsed["hook_output"].(map[string]interface{})
	if output["decision"] != "deny" {
		t.Fatalf("OpenHands hook_output=%#v, want decision=deny", parsed["hook_output"])
	}
}
