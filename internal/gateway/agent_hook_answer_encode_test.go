// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// GAP-1097: an Antigravity confirmation whose output cannot be encoded keeps
// its native ask instead of an empty success body.
func TestHandleAgentHookAntigravityConfirmSurvivesOutputEncodingFailure(t *testing.T) {
	useHookRuntimeForTest(t, "antigravity", func() agentHookResponse {
		return agentHookResponse{
			Action: "confirm", RawAction: "confirm", Mode: "action", Reason: "review this command",
			HookOutput: map[string]interface{}{"decision": "force_ask", "bad": math.NaN()},
		}
	})
	store, logger := testStoreAndLogger(t)
	api := &APIServer{store: store, logger: logger}
	answer, row := postAntigravityConfirmForTest(t, api, "encoding-confirm")
	if answer.Action != "confirm" || answer.Output.Decision != "force_ask" {
		t.Fatalf("native answer=%+v, want the audited confirm with force_ask", answer)
	}
	if row.Structured["action"] != "confirm" || row.Enforced {
		t.Fatalf("audit row=%+v, want the confirmation the hook was given", row.Structured)
	}
}

type antigravityConfirmAnswer struct {
	Action string `json:"action"`
	Output struct {
		Decision string `json:"decision"`
	} `json:"hook_output"`
}

func postAntigravityConfirmForTest(t *testing.T, api *APIServer, session string) (antigravityConfirmAnswer, audit.Event) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/antigravity/hook", strings.NewReader(
		`{"hook_event_name":"PreToolUse","session_id":"`+session+`","toolCall":{"name":"run_command","args":{"CommandLine":"echo ok"}}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DefenseClaw-Antigravity-Event", "PreToolUse")
	w := httptest.NewRecorder()
	api.handleAgentHook("antigravity").ServeHTTP(w, req)
	var answer antigravityConfirmAnswer
	if err := json.Unmarshal(w.Body.Bytes(), &answer); err != nil {
		t.Fatalf("native hook cannot decode the answer: status=%d body=%q: %v", w.Code, w.Body.String(), err)
	}
	return answer, soleHookDecisionForTest(t, api.store)
}
