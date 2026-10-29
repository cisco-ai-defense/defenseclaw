// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// One hook call is one decision: the audit row, the metrics and the native
// answer come from the same finalized verdict, whatever panics after it.

func useHookRuntimeForTest(t *testing.T, name string, evaluate func() agentHookResponse) {
	t.Helper()
	previous, had := hookProfileRuntimes[name]
	hookProfileRuntimes[name] = func(profile connector.HookProfile) hookProfileRuntime {
		runtime := defaultHookProfileRuntime(profile)
		runtime.Evaluate = func(*APIServer, context.Context, agentHookRequest, []byte, map[string]interface{}) agentHookResponse {
			return evaluate()
		}
		return runtime
	}
	t.Cleanup(func() {
		if had {
			hookProfileRuntimes[name] = previous
		} else {
			delete(hookProfileRuntimes, name)
		}
	})
}

// GAP-1096: a notifier panic after the decision was finalized neither
// finalizes it again nor replaces its answer.
func TestHandleAgentHookNotificationPanicKeepsTheOneFinalizedDecision(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	api := &APIServer{store: store, logger: logger}
	api.webhookSource = func() *WebhookDispatcher { panic("synthetic notification panic after finalization") }
	useHookRuntimeForTest(t, "hermes", func() agentHookResponse {
		return agentHookResponse{Action: "block", RawAction: "block", Mode: "action", Reason: "finalized policy block"}
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hermes/hook", strings.NewReader(
		`{"hook_event_name":"pre_tool_call","session_id":"sess-notify-panic","tool_name":"shell"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	api.handleAgentHook("hermes").ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var answer struct {
		Action string `json:"action"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &answer); err != nil {
		t.Fatalf("answer=%q: %v", w.Body.String(), err)
	}
	row := soleHookDecisionForTest(t, store)
	if answer.Action != "block" || answer.Reason != "finalized policy block" || row.Structured["action"] != answer.Action {
		t.Fatalf("answer=%+v, audit=%+v; want one matching finalized block", answer, row.Structured)
	}
}
