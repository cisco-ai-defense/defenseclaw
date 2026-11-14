// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// Inside a hook call the requested tool call is stored in the hook_decision
// row only (tool.invocation.requested is exported, not written), and the
// enterprise live check still finds the call by its tool call id (#1384).
func TestHookToolRequestIsExportOnlyInACallAndStillFound(t *testing.T) {
	f := newAuditFailureHookFixture(t, "open")
	started := time.Now().UTC()
	body := mustBenchJSON(t, map[string]any{"hook_event_name": "PreToolUse", "session_id": "s-tool-export", "cwd": t.TempDir(),
		"tool_name": "Bash", "tool_use_id": "toolu_export_only_1", "tool_input": map[string]any{"command": "git status"}})
	rec := httptest.NewRecorder()
	f.api.handleAgentHook("claudecode").ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %.200s", rec.Code, rec.Body.String())
	}
	db, err := sql.Open("sqlite", "file:"+f.path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var requested, decisions int
	deadline := time.Now().Add(5 * time.Second)
	for {
		_ = db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event_name = ?`, "tool.invocation.requested").Scan(&requested)
		_ = db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event_name = ?`, "hook_decision").Scan(&decisions)
		if decisions > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if decisions == 0 {
		t.Fatal("no hook_decision row")
	}
	if requested != 0 {
		t.Fatalf("%d local tool.invocation.requested rows inside a hook call, want 0", requested)
	}
	evidence, err := audit.FindHookToolInvocation(t.Context(), f.path, audit.HookToolInvocationQuery{
		Connector: "claudecode", ToolCallID: "toolu_export_only_1", Since: started,
	})
	if err != nil || !evidence.Matched {
		t.Fatalf("live check did not find the call: %+v, %v", evidence, err)
	}
}
