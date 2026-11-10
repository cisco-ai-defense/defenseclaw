// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// A call that carries the id of an earlier, already audited call is an exact
// replay. A replay of an allow adds no second row, but a block always has its
// own row: a denied call never vanishes from the audit (GAP-1060). A replayed
// allow collapses only into an earlier allow: after a block it has its own row.
func TestReplayedToolUseIDBlockStillWritesItsAuditRow(t *testing.T) {
	installCorrelationHMACForTest()
	store, logger := testStoreAndLogger(t)
	api := &APIServer{store: store, logger: logger}
	profile := api.hookProfileForConnector("claudecode")

	rows := func() int {
		t.Helper()
		events, err := store.ListEvents(500)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, ev := range events {
			if ev.Action == string(audit.ActionConnectorHook) {
				n++
			}
		}
		return n
	}
	allow := agentHookResponse{Action: "allow", RawAction: "allow", Mode: "action"}
	block := agentHookResponse{Action: "block", RawAction: "block", Mode: "action", Reason: "policy", Severity: "HIGH"}
	// deliver runs one hook call as the handler does: correlate, answer, write
	// the row, and mark the receipt once the row is committed.
	deliver := func(id string, resp agentHookResponse) agentHookRequest {
		t.Helper()
		payload := map[string]interface{}{
			"hook_event_name": "PreToolUse", "session_id": "session-1060", "tool_use_id": id,
			"tool_name": "Bash", "tool_input": map[string]interface{}{"command": "echo " + id},
		}
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		req := normalizeAgentHookRequestWithProfile("claudecode", payload, profile)
		ctx, req, err := api.correlateHookOccurrence(t.Context(), profile, req, raw)
		if err != nil {
			t.Fatalf("%s: correlate: %v", id, err)
		}
		finalization := api.finalizeAgentHook(ctx, "claudecode", req, resp, nil, raw, time.Millisecond, false, nil)
		if finalization.Response.Action != resp.Action {
			t.Fatalf("%s: answer changed from %s to %s", id, resp.Action, finalization.Response.Action)
		}
		if finalization.AuditPersisted {
			if err := api.finalizeHookCorrelationReceipt(t.Context(), req.CorrelationReceipt); err != nil {
				t.Fatal(err)
			}
		}
		return req
	}
	step := func(name string, id string, resp agentHookResponse, wantReplay bool, wantRows int) {
		t.Helper()
		before := rows()
		req := deliver(id, resp)
		if req.SuppressCorrelationEmit != wantReplay {
			t.Fatalf("%s: replay = %t, want %t", name, req.SuppressCorrelationEmit, wantReplay)
		}
		if got := rows() - before; got != wantRows {
			t.Fatalf("%s: new connector-hook rows = %d, want %d", name, got, wantRows)
		}
	}

	step("first block", "toolu_blocked", block, false, 1)
	step("first allow", "toolu_allowed", allow, false, 1)
	// The benign twin: a replayed allow stays silent.
	step("replayed allow", "toolu_allowed", allow, true, 0)
	// The id re-used by a denied call: its block row is written again.
	step("block answering an id that earlier got an allow", "toolu_allowed", block, true, 1)
	step("replayed block", "toolu_blocked", block, true, 1)
	step("replayed block again", "toolu_blocked", block, true, 1)
	// The id re-sent after a block and now answered allow: the only earlier
	// record is a block, so the allow is recorded too, then repeats stay silent.
	step("allow answering an id that earlier got a block", "toolu_blocked", allow, true, 1)
	step("replayed allow after that allow", "toolu_blocked", allow, true, 0)
	// A non-allow, non-block answer is its own delivery as well.
	alert := agentHookResponse{Action: "alert", RawAction: "alert", Mode: "action", Reason: "policy", Severity: "MEDIUM"}
	step("alert answering an id that earlier got an allow", "toolu_allowed", alert, true, 1)
	step("allow answering an id that earlier got an alert", "toolu_allowed", allow, true, 1)
}
