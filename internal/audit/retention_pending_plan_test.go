// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"strings"
	"testing"
	"time"
)

// GAP-1979: the event batch tested the pending operations with an OR of the
// start and terminal columns. Every open operation has the terminal column
// NULL, so a full ANALYZE (or statistics taken while the table was small)
// calls that index one value; SQLite then scanned the operations once per
// candidate event. Live on managed RHEL with 40,000 open operations and
// 40,000 old events, every benign hook took 1.4 s instead of 0.15 s for 95 to
// 180 s after a gateway start while retention held the writer. Each pending
// operation and relationship column must be its own indexed lookup, whatever
// the statistics say.
func TestRetentionEventBatchLooksUpPendingOperationsByIndex(t *testing.T) {
	store, _ := newRetentionStores(t)
	for _, statement := range []string{
		`ANALYZE`,
		`DELETE FROM sqlite_stat1 WHERE tbl IN ('correlation_pending_operations', 'correlation_relationships', 'correlation_events')`,
		`INSERT INTO sqlite_stat1(tbl, idx, stat) VALUES
			('correlation_pending_operations', 'idx_correlation_pending_terminal_event', '40000 40000'),
			('correlation_pending_operations', 'idx_correlation_pending_start_event', '40000 1'),
			('correlation_pending_operations', 'idx_correlation_pending_status', '40000 40000 40000 40000 40000 40000 40000 40000 1'),
			('correlation_pending_operations', 'idx_correlation_pending_exact', '40000 40000 40000 40000 1 1 1 1 1'),
			('correlation_pending_operations', 'sqlite_autoindex_correlation_pending_operations_1', '40000 40000 40000 40000 1 1 1 1'),
			('correlation_relationships', 'idx_correlation_relationships_from', '40000 40000 40000 40000'),
			('correlation_relationships', 'idx_correlation_relationships_to', '40000 40000 40000 40000'),
			('correlation_events', 'idx_correlation_events_received', '80000 1 1'),
			('correlation_events', 'sqlite_autoindex_correlation_events_1', '80000 1')`,
		`ANALYZE sqlite_schema`,
	} {
		if _, err := store.db.Exec(statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	statement, err := correlationRetentionDeleteStatement(RetentionCorrelationEvents)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UnixNano()
	rows, err := store.db.Query(`EXPLAIN QUERY PLAN `+statement, now, now, RetentionBatchSize)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan []string
	terminalLookup := false
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, detail)
		if strings.HasPrefix(detail, "SEARCH operation") &&
			strings.Contains(detail, "idx_correlation_pending_terminal_event (terminal_semantic_event_id=?)") {
			terminalLookup = true
		}
		if strings.HasPrefix(detail, "SCAN operation") || strings.HasPrefix(detail, "SCAN relationship") {
			t.Errorf("a keep test scans its table per candidate event: %q", detail)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !terminalLookup {
		t.Errorf("event batch does not look pending operations up by terminal_semantic_event_id:\n%s", strings.Join(plan, "\n"))
	}
	if t.Failed() {
		t.Logf("plan:\n%s", strings.Join(plan, "\n"))
	}
}
