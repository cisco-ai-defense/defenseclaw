// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// rel-1-0-10:GAP-1172: the Claude Code native hook delivers PreToolUse with a
// delivery receipt, so the call gets occurrence IDs (journalHookDelivery)
// although a per-user gateway journals nothing and nothing recovers it. A
// benign allow of such a call keeps one local hook row, its hook_decision
// row, like every other live call, and still exports the connector-hook
// record. Before the fix every benign Claude Code tool call also kept a
// local connector-hook row.
func TestReceiptCapablePerUserAllowKeepsOneLocalHookRow(t *testing.T) {
	remote := newHookRemoteRecorder()
	f := newPerUserHookFixtureExportingTo(t, remote)
	cwd := t.TempDir()
	body, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "session_id": "s-gap1172", "cwd": cwd,
		"transcript_path": cwd + "/t.jsonl", "permission_mode": "default", "tool_name": "Bash",
		"tool_use_id": "toolu_gap1172_1", "tool_input": map[string]any{"command": "echo marker", "description": "Print a marker"}})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook",
		strings.NewReader(string(body)+hookexec.HookDeliveryReceiptAck))
	request.Header.Set(hookexec.HookDeliveryReceiptHeader, "1")
	request.Header.Set(hookexec.HookDeliveryPayloadBytesHeader, strconv.Itoa(len(body)))
	request.Header.Set("Content-Type", "application/json")
	reply := &recordFullDuplexStatusWriter{ResponseRecorder: httptest.NewRecorder()}
	f.api.handleAgentHook("claudecode").ServeHTTP(reply, request)
	if reply.finalStatus != http.StatusOK {
		t.Fatalf("status %d: %.300s", reply.finalStatus, reply.Body.String())
	}

	deadline := time.Now().Add(10 * time.Second)
	for remote.exportedWithEvent("legacy.audit.connector.hook") == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := remote.exportedWithEvent("legacy.audit.connector.hook"); got != 1 {
		t.Errorf("exported connector-hook records = %d, want 1 (the export is unchanged)", got)
	}
	db, err := sql.Open("sqlite", "file:"+f.path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var decisionID string
	if err := db.QueryRow(`SELECT id FROM audit_events WHERE event_name = 'hook_decision'`).Scan(&decisionID); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(decisionID, "-decision") {
		t.Fatalf("hook_decision id %q: the call did not take the receipt path (no occurrence IDs)", decisionID)
	}
	local := localRowsByEvent(t, f.path)
	if local["hook_decision"] != 1 || local["legacy.audit.connector.hook"] != 0 {
		t.Fatalf("local rows by event = %v, want one hook_decision and no connector-hook row", local)
	}
}
