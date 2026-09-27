// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// TestHandleAgentHook_PostEvaluationPanicSandboxFailsClosed tests the
// scenario where a panic occurs AFTER safeEvaluateHook returns successfully
// but BEFORE the response is finalized. For sandbox hooks, these panics must
// fail closed (action=block), not fail open (action=allow), because the
// sandbox hook is the only gate on tool execution.
//
// This test demonstrates the vulnerability: the outer defer in handleAgentHook
// catches post-evaluation panics and creates a fail-open response without
// checking sandboxHookForConnector. The fix should apply the same fail-closed
// transformation in the outer defer as is applied at line 457 for evaluator
// panics.
func TestHandleAgentHook_PostEvaluationPanicSandboxFailsClosed(t *testing.T) {
	// Inject a panic in the post-evaluation EmitLLMEvent call by enabling
	// managed enterprise mode (so EmitLLMEvent is deferred until after
	// evaluation) and making the runtime's EmitLLMEvent panic.
	prev := managedEnterpriseActive.Load()
	managedEnterpriseActive.Store(true)
	defer managedEnterpriseActive.Store(prev)

	prevRuntime, had := hookProfileRuntimes["hermes"]
	hookProfileRuntimes["hermes"] = func(profile connector.HookProfile) hookProfileRuntime {
		runtime := defaultHookProfileRuntime(profile)
		// Make the EmitLLMEvent panic. In managed enterprise mode, this is
		// called AFTER safeEvaluateHook returns (line 509 in agent_hook.go),
		// so the panic occurs in the post-evaluation path and is caught by
		// the outer defer, not by safeEvaluateHook's inner defer.
		runtime.EmitLLMEvent = func(*APIServer, context.Context, agentHookRequest, []byte, map[string]interface{}, []string) {
			panic("synthetic post-evaluation panic for sandbox test")
		}
		return runtime
	}
	defer func() {
		if had {
			hookProfileRuntimes["hermes"] = prevRuntime
		} else {
			delete(hookProfileRuntimes, "hermes")
		}
	}()

	api := &APIServer{}
	handler := http.HandlerFunc(api.handleAgentHook("hermes"))
	body, _ := json.Marshal(map[string]interface{}{
		"hook_event_name": "pre_tool_call",
		"session_id":      "session-sandbox-post-eval-panic",
		"agent_id":        "hermes-test",
		"tool_name":       "shell",
		"tool_input":      map[string]interface{}{"command": "echo marker"},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hermes/hook", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	// Authenticate as a sandbox request for the hermes connector
	binding := sandboxauth.Binding{ID: "sb_post_panic", Connector: sandboxauth.CanonicalConnector("hermes")}
	req = req.WithContext(sandboxauth.WithRequest(req.Context(), binding, nil))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%s", w.Code, w.Body.String())
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("response body is not valid JSON after panic: %v body=%s", err, w.Body.String())
	}

	// BUG: The response action is "allow" (fail-open) when it should be "block"
	// (fail-closed) for sandbox hooks. The outer defer creates a fail-open
	// response without checking sandboxHookForConnector.
	if got, _ := parsed["action"].(string); got != "block" {
		t.Fatalf("sandbox post-evaluation panic action = %q, want block (sandbox hooks must fail closed); body=%s", got, w.Body.String())
	}
	if reason, _ := parsed["reason"].(string); !strings.HasPrefix(reason, "Blocked by DefenseClaw") {
		t.Errorf("sandbox panic reason = %q, want a plain block reason", reason)
	}
}
