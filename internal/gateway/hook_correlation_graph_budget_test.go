// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"
)

// correlationGraphBudgetPerDecision is the most bytes of the local
// correlation graph (every correlation_* table and
// guardrail_chain_pending_actions, with their indexes) one benign per-user
// Claude Code hook decision may leave once its tool call settled: a
// PreToolUse and its PostToolUse are two decisions. At fd29bfa7d3 a decision
// left 8.8 KB. S8 R5 removed the indexes no query uses, the identifiers and
// cross-rail claims no reader uses, the stored copy of the evidence every
// semantic-event edge implies, the resolved pending operation and the
// settled call's replay receipt: 5.5 KB is left. More than half of it is
// the call's correlation observations (5 rows per decision, with 9
// indexes), which R5 does not change; the rest is the events, the
// session identifier, and the edges with their keys.
const correlationGraphBudgetPerDecision = 5700

// correlationGraphBytes is the page bytes of the correlation graph tables
// and their indexes in the store at path, by name.
func correlationGraphBytes(t *testing.T, path string) map[string]int64 {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT stat.name, SUM(stat.pgsize) FROM dbstat AS stat
		JOIN sqlite_master AS object ON object.name=stat.name
		WHERE object.tbl_name LIKE 'correlation\_%' ESCAPE '\'
			OR object.tbl_name='guardrail_chain_pending_actions'
		GROUP BY stat.name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	result := map[string]int64{}
	for rows.Next() {
		var name string
		var size int64
		if err := rows.Scan(&name, &size); err != nil {
			t.Fatal(err)
		}
		result[name] = size
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}

// TestClaudeCodeSettledToolCallCorrelationGraphBudget sends benign
// PreToolUse and PostToolUse pairs through the real per-user Claude Code hook
// handler and store, and holds the correlation graph bytes each decision of
// a settled call adds to correlationGraphBudgetPerDecision.
func TestClaudeCodeSettledToolCallCorrelationGraphBudget(t *testing.T) {
	fixture := newAuditFailureHookFixture(t, "open")
	cwd := t.TempDir()
	send := func(event string, index int) {
		payload := map[string]any{
			"hook_event_name": event, "session_id": "graph-budget", "cwd": cwd,
			"tool_name": "Bash", "tool_use_id": fmt.Sprintf("toolu_graph_%06d", index),
			"tool_input": map[string]any{"command": "git status"},
		}
		if event == "PostToolUse" {
			payload["tool_response"] = map[string]any{"stdout": "On branch main", "stderr": "", "interrupted": false}
		}
		recorder := httptest.NewRecorder()
		fixture.api.handleAgentHook("claudecode").ServeHTTP(recorder,
			httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", bytes.NewReader(mustBenchJSON(t, payload))))
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s %d: status %d body %.200s", event, index, recorder.Code, recorder.Body.String())
		}
	}
	// The first calls of a session write its one-time rows and grow the
	// tables past their first pages.
	for index := 0; index < 20; index++ {
		send("PreToolUse", index)
		send("PostToolUse", index)
	}
	// A receipt mark may finish after the answer (hookReceiptFollowUpWait).
	time.Sleep(time.Second)
	before := correlationGraphBytes(t, fixture.path)
	const measured = 200
	for index := 100; index < 100+measured; index++ {
		send("PreToolUse", index)
		send("PostToolUse", index)
	}
	time.Sleep(time.Second)
	after := correlationGraphBytes(t, fixture.path)
	names := make([]string, 0, len(after))
	var total int64
	for name, size := range after {
		names = append(names, name)
		total += size - before[name]
	}
	sort.Slice(names, func(i, j int) bool {
		return after[names[i]]-before[names[i]] > after[names[j]]-before[names[j]]
	})
	for _, name := range names {
		if grown := after[name] - before[name]; grown > 0 {
			t.Logf("%-52s %6.0f bytes per settled call", name, float64(grown)/measured)
		}
	}
	// Two decisions per settled call.
	perDecision := float64(total) / (2 * measured)
	t.Logf("correlation graph: %.0f bytes per settled call, %.0f per decision", float64(total)/measured, perDecision)
	if perDecision > correlationGraphBudgetPerDecision {
		t.Fatalf("a settled Claude Code decision left %.0f bytes of correlation graph; the budget is %d",
			perDecision, correlationGraphBudgetPerDecision)
	}
}
