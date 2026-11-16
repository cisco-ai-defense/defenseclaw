// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// A hook whose correlation could not be written (concurrent hooks of one
// session, a busy store) still names its tool call and turn on its audit
// records: the connector-hook row and the envelope the hook_decision record
// reads (GAP-0980).
func TestHookAuditRecordsKeepTheToolIDWhenCorrelationFails(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	api := &APIServer{store: store, logger: logger}
	req := agentHookRequest{
		ConnectorName: "claudecode", HookEventName: "PreToolUse", SessionID: "session-0980",
		TurnID: "turn-0980", ToolInvocationID: "toolu-0980", ToolName: "Bash",
		SuppressCorrelationEmit: true, CorrelationUnavailable: true,
	}
	ctx := enrichAgentHookContext(context.Background(), req)
	if env := audit.EnvelopeFromContext(ctx); env.ToolID != req.ToolInvocationID || env.TurnID != req.TurnID {
		t.Fatalf("envelope tool=%q turn=%q, want %q and %q", env.ToolID, env.TurnID, req.ToolInvocationID, req.TurnID)
	}
	resp := agentHookResponse{Action: "allow", RawAction: "allow", Mode: "observe"}
	if !api.finalizeAgentHook(ctx, "claudecode", req, resp, nil, []byte(`{}`), time.Millisecond, false, nil).AuditPersisted {
		t.Fatal("the connector-hook row was not persisted")
	}
	events, err := store.ListEvents(50)
	if err != nil {
		t.Fatal(err)
	}
	rows := 0
	for _, ev := range events {
		if ev.Action != string(audit.ActionConnectorHook) {
			continue
		}
		rows++
		if ev.ToolID != req.ToolInvocationID {
			t.Errorf("connector-hook row tool_id = %q, want %q", ev.ToolID, req.ToolInvocationID)
		}
	}
	if rows != 1 {
		t.Fatalf("connector-hook rows = %d, want 1", rows)
	}
}

// On a managed host every account's hooks share one connector instance.
// The same hook body from another verified account is that account's own
// call: it gets its own occurrence and decision records, never the first
// account's replay. A retry from the same account stays a replay
// (GAP-1028).
func TestHookReplayReceiptIsScopedToTheVerifiedCaller(t *testing.T) {
	installCorrelationHMACForTest()
	server, store := newHookCorrelationServer(t, filepath.Join(t.TempDir(), "audit.db"))
	defer store.Close() //nolint:errcheck
	profile := server.hookProfileForConnector("claudecode")
	payload := map[string]interface{}{
		"hook_event_name": "PreToolUse", "session_id": "shared-a", "tool_use_id": "shared-a",
		"tool_name": "Bash", "tool_input": map[string]interface{}{"command": "echo ok"},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	send := func(uid int) agentHookRequest {
		t.Helper()
		ctx := withManagedHookPeer(t.Context(), managedHookPeer{UID: uid, Name: fmt.Sprintf("eng-%d", uid)})
		req := normalizeAgentHookRequestWithProfile("claudecode", payload, profile)
		_, req, err := server.correlateHookOccurrence(ctx, profile, req, raw)
		if err != nil {
			t.Fatalf("uid %d: correlate: %v", uid, err)
		}
		if !req.SuppressCorrelationEmit {
			if req.CorrelationReceipt == nil {
				t.Fatalf("uid %d: the hook has no delivery receipt", uid)
			}
			persistCanonicalCorrelationObservation(t, store, req.SemanticEventID, "tool.start")
			if err := server.finalizeHookCorrelationReceipt(t.Context(), req.CorrelationReceipt); err != nil {
				t.Fatal(err)
			}
		}
		return req
	}
	const eng1, eng2 = 94404135, 94404136
	first := send(eng1)
	if first.SuppressCorrelationEmit {
		t.Fatal("the first call was suppressed")
	}
	other := send(eng2)
	if other.SuppressCorrelationEmit || other.SemanticEventID == first.SemanticEventID {
		t.Fatalf("another account's identical call was taken as a replay: suppressed=%t semantic=%s first=%s",
			other.SuppressCorrelationEmit, other.SemanticEventID, first.SemanticEventID)
	}
	for _, retry := range []struct {
		uid  int
		want agentHookRequest
	}{{eng2, other}, {eng1, first}} {
		got := send(retry.uid)
		if !got.SuppressCorrelationEmit || got.SemanticEventID != retry.want.SemanticEventID {
			t.Fatalf("uid %d: a retry of its own call was not its replay: suppressed=%t semantic=%s want %s",
				retry.uid, got.SuppressCorrelationEmit, got.SemanticEventID, retry.want.SemanticEventID)
		}
	}
}
