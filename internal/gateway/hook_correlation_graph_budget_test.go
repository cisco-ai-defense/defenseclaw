// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"database/sql"
	"fmt"
	"maps"
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
// semantic-event edge implies and the resolved pending operation. Half of
// what is left is the call's correlation observations (5 rows per decision,
// with 9 indexes), which R5 does not change; the rest is the events, the
// session identifier, the edges with their keys, and the start's replay
// receipt, which the settle cuts to an hour (correlationSettledReceiptTTL)
// but which is still there when this test measures. Pinned at the bytes
// measured on s8/recset (R4+R5 on rel/1.0.10) plus about 5 percent.
const correlationGraphBudgetPerDecision = 5200

// hookStoreBudgetPerBenignPreToolUse and hookStoreBudgetPerSettledPair are
// the most bytes of the whole local store (every table and index: the audit
// rows and the correlation graph) a benign per-user Claude Code PreToolUse,
// and a settled PreToolUse + PostToolUse pair, may add (S8 R4 + R5, #1384).
// 1.0.9 wrote 39.5 KB per PreToolUse. The owner accepted about 10.5 KB per
// decision for 1.0.10; the hook_decision row keeps its payload_json copy so
// a rollback to 1.0.9 still reads every decision. Pinned at the bytes
// measured on s8/recset (R4+R5 on rel/1.0.10) plus about 5 percent.
const (
	hookStoreBudgetPerBenignPreToolUse = 11300
	hookStoreBudgetPerSettledPair      = 33500
)

// storeObjectBytes is the page bytes of every table and index of the store
// at path, by name; graphOnly keeps the correlation graph tables and their
// indexes.
func storeObjectBytes(t *testing.T, path string, graphOnly bool) map[string]int64 {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	query := `SELECT stat.name, SUM(stat.pgsize) FROM dbstat AS stat GROUP BY stat.name`
	if graphOnly {
		query = `SELECT stat.name, SUM(stat.pgsize) FROM dbstat AS stat
		JOIN sqlite_master AS object ON object.name=stat.name
		WHERE object.tbl_name LIKE 'correlation\_%' ESCAPE '\'
			OR object.tbl_name='guardrail_chain_pending_actions'
		GROUP BY stat.name`
	}
	rows, err := db.Query(query)
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

// correlationGraphBytes is the page bytes of the correlation graph tables
// and their indexes in the store at path, by name.
func correlationGraphBytes(t *testing.T, path string) map[string]int64 {
	t.Helper()
	return storeObjectBytes(t, path, true)
}

// settledStoreBytes is read once every receipt mark has landed (they may
// finish after the answer, hookReceiptFollowUpWait) and two reads 100 ms
// apart agree, so a slow runner measures the same writes as a fast one.
func settledStoreBytes(t *testing.T, path string, read func(*testing.T, string) map[string]int64) map[string]int64 {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	previous := read(t, path)
	for {
		time.Sleep(100 * time.Millisecond)
		current := read(t, path)
		unaccepted := countCorrelationRowsForTest(t, path,
			`SELECT COUNT(*) FROM correlation_receipts WHERE accepted_time_unix_nano IS NULL`)
		if unaccepted == 0 && maps.Equal(previous, current) {
			return current
		}
		if time.Now().After(deadline) {
			t.Fatalf("the store did not settle in 30 s (%d receipts unaccepted)", unaccepted)
		}
		previous = current
	}
}

// sendBudgetClaudeHook sends one benign per-user Claude Code hook call of
// tool call index through the real handler.
func sendBudgetClaudeHook(t *testing.T, fixture auditFailureHookFixture, cwd, session, event string, index int) {
	t.Helper()
	payload := map[string]any{
		"hook_event_name": event, "session_id": session, "cwd": cwd,
		"tool_name": "Bash", "tool_use_id": fmt.Sprintf("toolu_%s_%06d", session, index),
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

// measureHookStoreGrowth sends the calls of 20 tool calls (the first calls
// of a session write its one-time rows and grow the tables past their first
// pages), then those of measured more, and returns the bytes read gains over
// the measured calls, logging the objects that grew.
func measureHookStoreGrowth(
	t *testing.T,
	session string,
	events []string,
	measured int,
	read func(*testing.T, string) map[string]int64,
) int64 {
	t.Helper()
	fixture := newAuditFailureHookFixture(t, "open")
	cwd := t.TempDir()
	for index := range 20 {
		for _, event := range events {
			sendBudgetClaudeHook(t, fixture, cwd, session, event, index)
		}
	}
	before := settledStoreBytes(t, fixture.path, read)
	for index := 100; index < 100+measured; index++ {
		for _, event := range events {
			sendBudgetClaudeHook(t, fixture, cwd, session, event, index)
		}
	}
	after := settledStoreBytes(t, fixture.path, read)
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
			t.Logf("%-52s %6.0f bytes per tool call", name, float64(grown)/float64(measured))
		}
	}
	return total
}

// TestClaudeCodeSettledToolCallCorrelationGraphBudget sends benign
// PreToolUse and PostToolUse pairs through the real per-user Claude Code hook
// handler and store, and holds the correlation graph bytes each decision of
// a settled call adds to correlationGraphBudgetPerDecision.
func TestClaudeCodeSettledToolCallCorrelationGraphBudget(t *testing.T) {
	const measured = 200
	total := measureHookStoreGrowth(t, "graph-budget", []string{"PreToolUse", "PostToolUse"}, measured, correlationGraphBytes)
	// Two decisions per settled call.
	perDecision := float64(total) / (2 * measured)
	t.Logf("correlation graph: %.0f bytes per settled call, %.0f per decision", float64(total)/measured, perDecision)
	if perDecision > correlationGraphBudgetPerDecision {
		t.Fatalf("a settled Claude Code decision left %.0f bytes of correlation graph; the budget is %d",
			perDecision, correlationGraphBudgetPerDecision)
	}
}

// TestClaudeCodeBenignPreToolUseStoreBudget holds the whole-store bytes of a
// benign per-user Claude Code PreToolUse to
// hookStoreBudgetPerBenignPreToolUse.
func TestClaudeCodeBenignPreToolUseStoreBudget(t *testing.T) {
	const measured = 300
	allObjects := func(t *testing.T, path string) map[string]int64 { return storeObjectBytes(t, path, false) }
	total := measureHookStoreGrowth(t, "pre-budget", []string{"PreToolUse"}, measured, allObjects)
	perCall := float64(total) / measured
	t.Logf("store: %.0f bytes per benign PreToolUse", perCall)
	if perCall > hookStoreBudgetPerBenignPreToolUse {
		t.Fatalf("a benign Claude Code PreToolUse added %.0f bytes to the store; the budget is %d",
			perCall, hookStoreBudgetPerBenignPreToolUse)
	}
}

// TestClaudeCodeSettledToolCallStoreBudget holds the whole-store bytes of a
// settled benign per-user Claude Code PreToolUse + PostToolUse pair to
// hookStoreBudgetPerSettledPair.
func TestClaudeCodeSettledToolCallStoreBudget(t *testing.T) {
	const measured = 200
	allObjects := func(t *testing.T, path string) map[string]int64 { return storeObjectBytes(t, path, false) }
	total := measureHookStoreGrowth(t, "pair-budget", []string{"PreToolUse", "PostToolUse"}, measured, allObjects)
	perPair := float64(total) / measured
	t.Logf("store: %.0f bytes per settled pair, %.0f per decision", perPair, perPair/2)
	if perPair > hookStoreBudgetPerSettledPair {
		t.Fatalf("a settled Claude Code tool call added %.0f bytes to the store; the budget is %d",
			perPair, hookStoreBudgetPerSettledPair)
	}
}
