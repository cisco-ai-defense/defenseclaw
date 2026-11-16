// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"strings"
	"testing"
	"time"
)

// GAP-1862, GAP-1908: the relationship retention batch tested every
// candidate against the protected node set with an OR of the from and to
// pairs, and joined the evidence nodes on kind alone. SQLite then scanned the
// whole materialized set once per candidate: on a 1.75 GB managed store one
// batch held the only writer connection for 86 s after each gateway start,
// and the hooks queued behind it failed closed. Every protected-node test
// must be an indexed (kind, id) lookup.
func TestRetentionRelationshipBatchLooksUpProtectedNodesByKey(t *testing.T) {
	store, _ := newRetentionStores(t)
	statement, err := correlationRetentionDeleteStatement(RetentionCorrelationRelationships)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UnixNano()
	rows, err := store.db.Query(`EXPLAIN QUERY PLAN `+statement, now, now, now, RetentionBatchSize)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var lookups int
	var plan []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, detail)
		if !strings.Contains(detail, " node") {
			continue
		}
		if strings.HasPrefix(detail, "SCAN node") || strings.HasSuffix(detail, "(kind=?)") {
			t.Errorf("protected nodes are scanned per candidate: %q", detail)
		}
		if strings.HasPrefix(detail, "SEARCH node") && strings.Contains(detail, "id=?") {
			lookups++
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if lookups < 3 {
		t.Errorf("want 3 keyed protected-node lookups (from, to, evidence), got %d:\n%s",
			lookups, strings.Join(plan, "\n"))
	}
}

// The event batch tests each receipt column with its own indexed lookup. With
// the planner statistics of a populated managed store (749 receipts, the
// conflict column NULL on every row), an OR of the two columns made SQLite
// scan the receipts once per candidate event: 3.4 s per batch on the
// 1.75 GB store, holding the writer connection (GAP-1862).
func TestRetentionEventBatchLooksUpReceiptsByIndex(t *testing.T) {
	store, _ := newRetentionStores(t)
	for _, statement := range []string{
		`ANALYZE`,
		`DELETE FROM sqlite_stat1 WHERE tbl IN ('correlation_receipts', 'correlation_events')`,
		`INSERT INTO sqlite_stat1(tbl, idx, stat) VALUES
			('correlation_receipts', 'idx_correlation_receipts_conflict_event', '749 749'),
			('correlation_receipts', 'idx_correlation_receipts_event', '749 1'),
			('correlation_receipts', 'idx_correlation_receipts_expiry', '749 1'),
			('correlation_receipts', 'sqlite_autoindex_correlation_receipts_1', '749 375 1 1'),
			('correlation_events', 'idx_correlation_events_received', '39106 1 1'),
			('correlation_events', 'sqlite_autoindex_correlation_events_1', '39106 1')`,
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
	eventLookup := false
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, detail)
		if strings.HasPrefix(detail, "SEARCH receipt") &&
			strings.Contains(detail, "idx_correlation_receipts_event (semantic_event_id=?)") {
			eventLookup = true
		}
		if detail == "SCAN receipt" {
			t.Errorf("receipts are scanned per candidate event: %q", detail)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !eventLookup {
		t.Errorf("event batch does not look receipts up by semantic_event_id:\n%s", strings.Join(plan, "\n"))
	}
}
