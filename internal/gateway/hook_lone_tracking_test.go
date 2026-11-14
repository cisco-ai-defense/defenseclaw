// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// loneIDsForTest lists the lone hook_decision rows of the store at path by
// the audit_hook_lone rule (tracked) or the projected-record rule.
func loneIDsForTest(t *testing.T, path string, tracked bool) []string {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT id FROM audit_events WHERE ` + audit.LoneHookDecisionSQL("", tracked))
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	sort.Strings(ids)
	return ids
}

func loneEntriesForTest(t *testing.T, path string) int {
	t.Helper()
	return countCorrelationRowsForTest(t, path, `SELECT COUNT(*) FROM audit_hook_lone`)
}

// TestGatewayListsExactlyItsLoneHookDecisions: the gateway lists in
// audit_hook_lone exactly the hook_decision rows the projected-record rule
// finds alone (rel-1-0-10:GAP-0316): each benign per-user tool call's row of
// record (PreToolUse and PostToolUse), and the fail-mode decision of a call
// whose audit write failed until the failure report writes its row.
func TestGatewayListsExactlyItsLoneHookDecisions(t *testing.T) {
	fixture := newAuditFailureHookFixture(t, "open")
	cwd := t.TempDir()
	for index := range 3 {
		tool := fmt.Sprintf("toolu_lone_%d", index)
		sendClaudeToolHookForTest(t, fixture, cwd, "PreToolUse", tool)
		sendClaudeToolHookForTest(t, fixture, cwd, "PostToolUse", tool)
	}
	assertLoneRulesAgreeForTest(t, fixture.path, 6)

	data := t.TempDir()
	fixture.api.scannerCfg.DataDir = data
	logPath := filepath.Join(data, "logs", hookFailuresFile)
	fixture.emitter.fail = true
	fixture.preToolUse(t, "toolu_lone_gap")
	fixture.emitter.fail = false
	if _, err := os.Stat(logPath); err != nil {
		t.Fatalf("the unaudited call left no failure line: %v", err)
	}
	before := assertLoneRulesAgreeForTest(t, fixture.path, -1)
	if err := reportHookFailureCallsIn(filepath.Dir(logPath), fixture.api.logger, time.Now()); err != nil {
		t.Fatal(err)
	}
	after := assertLoneRulesAgreeForTest(t, fixture.path, -1)
	if before < 6 || after > before {
		t.Fatalf("lone rows: %d before the report, %d after; want at least 6 and no more after", before, after)
	}
}

// assertLoneRulesAgreeForTest requires both lone rules to list the same rows
// (want of them, or any number for want < 0) and returns the count.
func assertLoneRulesAgreeForTest(t *testing.T, path string, want int) int {
	t.Helper()
	tracked, records := loneIDsForTest(t, path, true), loneIDsForTest(t, path, false)
	if fmt.Sprint(tracked) != fmt.Sprint(records) || (want >= 0 && len(tracked) != want) {
		t.Fatalf("lone rows: tracked %d %v, record rule %d %v; want the same %d", len(tracked), tracked, len(records), records, want)
	}
	return len(tracked)
}

// TestManagedHookCallsListNoLoneDecision: a managed call keeps its
// connector-hook row, so it writes nothing to audit_hook_lone: the managed
// hook path pays no insert (rel-1-0-10:GAP-0316).
func TestManagedHookCallsListNoLoneDecision(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	for index := range 3 {
		f.offer(t, fmt.Sprintf("managed-lone-%d", index), hookexec.HookDeliveryConfirmed)
	}
	if got := loneEntriesForTest(t, f.path); got != 0 {
		t.Fatalf("managed calls listed %d lone decisions, want 0", got)
	}
	if got := loneIDsForTest(t, f.path, false); len(got) != 0 {
		t.Fatalf("the record rule finds lone managed decisions %v, want none", got)
	}
}
