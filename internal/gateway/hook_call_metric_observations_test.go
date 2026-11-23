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
)

// The metrics a hook call records write no correlation observation row of
// their own: the call commits the observation of its log records and the
// metrics are exported after that commit (S8 R1, #1384). A benign PreToolUse
// wrote 9 metric observation rows before.
func TestHookCallMetricsWriteNoObservationRows(t *testing.T) {
	f := newAuditFailureHookFixture(t, "open")
	body := mustBenchJSON(t, map[string]any{"hook_event_name": "PreToolUse", "session_id": "s-metric-obs", "cwd": t.TempDir(),
		"tool_name": "Bash", "tool_use_id": "toolu_metric_obs_1", "tool_input": map[string]any{"command": "git status"}})
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
	count := func(signal string) int {
		var n int
		deadline := time.Now().Add(5 * time.Second)
		for {
			if err := db.QueryRow(`SELECT COUNT(*) FROM correlation_observations WHERE signal = ?`, signal).Scan(&n); err != nil {
				t.Fatal(err)
			}
			if signal != "logs" || n > 0 || time.Now().After(deadline) {
				return n
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	if logs := count("logs"); logs == 0 {
		t.Fatal("the hook call committed no log observation")
	}
	if metrics := count("metrics"); metrics != 0 {
		t.Fatalf("%d metric observation rows for one hook call, want 0", metrics)
	}
}
