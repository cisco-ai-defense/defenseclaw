// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"
	"time"
)

// GAP-1098: an identity-stage panic does not record a native block as
// unenforced.
func TestFinalizeAgentHookIdentityPanicKeepsNativeBlockEnforced(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	api := &APIServer{store: store, logger: logger,
		// A nil turn map makes the identity stamper panic before it sets
		// Enforced; the finalized verdict must already carry the bit.
		stepIdxBySession: map[string]*sessionStepState{"identity-panic": {turnToStep: nil}},
	}
	req := agentHookRequest{
		ConnectorName: "antigravity", HookEventName: "PreToolUse",
		SessionID: "identity-panic", TurnID: "turn-1", ToolName: "run_command",
	}
	resp := agentHookResponse{
		Action: "block", RawAction: "block", Mode: "action", Reason: "blocked command",
		HookOutput: map[string]interface{}{"decision": "deny", "reason": "blocked command"},
	}
	result := api.finalizeAgentHook(t.Context(), "antigravity", req, resp, nil, []byte(`{}`), time.Millisecond, false, nil)
	if !result.AuditPersisted || !result.Enforced || !result.notificationReady() {
		t.Fatalf("finalization=%+v, want a persisted, enforced, notification-ready native block", result)
	}
	if row := soleHookDecisionForTest(t, store); row.Structured["action"] != "block" || !row.Enforced {
		t.Fatalf("audit row=%+v, want the native block enforced", row.Structured)
	}
}
