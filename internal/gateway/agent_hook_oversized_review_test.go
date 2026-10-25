// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestBoundedPrefixAllowHasHighAuditSeverity(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Connector = "claudecode"
	store, logger := testStoreAndLogger(t)
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/claude-code/hook", strings.NewReader(`{
		"hook_event_name":"PreToolUse", "session_id":"s", "tool_name":"Bash",
		"tool_input":{"command":"echo safe"}, "bounded_prefix_review":true,
		"content_truncated":true}`))
	request.Header.Set("Content-Type", "application/json")
	reply := httptest.NewRecorder()
	api.handleAgentHook("claudecode").ServeHTTP(reply, request)
	if reply.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", reply.Code, reply.Body.String())
	}
	var answer agentHookResponse
	if err := json.Unmarshal(reply.Body.Bytes(), &answer); err != nil {
		t.Fatal(err)
	}
	if answer.Action != "allow" || answer.Severity != "HIGH" {
		t.Fatalf("bounded allow = %+v", answer)
	}
	events, err := store.ListEvents(20)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.Action == string(audit.ActionConnectorHook) && event.Severity == "HIGH" {
			return
		}
	}
	t.Fatalf("no HIGH connector-hook audit row: %+v", events)
}
