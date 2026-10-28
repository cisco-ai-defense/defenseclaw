// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// A tool call whose hook payload the connector's decoder cannot read is
// blocked with the could-not-read reason, and the refusal is recorded like
// every other block finding: its rule ID is in the response and in the
// connector-hook audit row, next to the reason.
func TestHandleAgentHook_UnreadableToolCallRecordsItsFinding(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "antigravity"
	store, logger := testStoreAndLogger(t)
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}
	body := `{"hook_event_name":"PreToolUse","session_id":"s-unparsed","tool_name":"Bash","tool_input":{"command":"echo ok"},"cwd":"/tmp"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/antigravity/hook", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DefenseClaw-Antigravity-Event", "PreToolUse")
	recorder := httptest.NewRecorder()
	api.handleAgentHook("antigravity").ServeHTTP(recorder, req)
	var parsed struct {
		Action     string          `json:"action"`
		RuleIDs    []string        `json:"rule_ids"`
		HookOutput json.RawMessage `json:"hook_output"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("status=%d body=%s: %v", recorder.Code, recorder.Body.String(), err)
	}
	if parsed.Action != "block" || !slices.Contains(parsed.RuleIDs, hookToolCallUnparsedRuleID) {
		t.Fatalf("action=%q rule_ids=%v, want block with %s: %s", parsed.Action, parsed.RuleIDs, hookToolCallUnparsedRuleID, recorder.Body.String())
	}
	if !strings.Contains(string(parsed.HookOutput), "DefenseClaw could not read the tool call") {
		t.Fatalf("hook_output=%s, want the could-not-read reason for the agent", parsed.HookOutput)
	}
	events, err := store.ListEvents(50)
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range events {
		if ev.Action != string(audit.ActionConnectorHook) {
			continue
		}
		if !strings.Contains(ev.Details, "rule_ids") || !strings.Contains(ev.Details, hookToolCallUnparsedRuleID) {
			t.Fatalf("connector-hook audit details = %q, want rule_ids with %s", ev.Details, hookToolCallUnparsedRuleID)
		}
		return
	}
	t.Fatalf("no connector-hook audit row in %d events", len(events))
}
