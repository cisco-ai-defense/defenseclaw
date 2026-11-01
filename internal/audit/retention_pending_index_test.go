// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"strings"
	"testing"
	"time"
)

// GAP-1790: the pending-operation retention batch read the whole
// correlation_pending_operations table inside its write transaction. With
// 70,000 open (active) operations on a cold managed store that held the
// writer 3.6 s after every gateway start. The batch must search the partial
// index of ended operations instead, whatever the statistics say.
func TestRetentionPendingOperationBatchSearchesTheEndedOperationsIndex(t *testing.T) {
	store, _ := newRetentionStores(t)
	for _, statement := range []string{
		`ANALYZE`,
		`DELETE FROM sqlite_stat1 WHERE tbl = 'correlation_pending_operations'`,
		`INSERT INTO sqlite_stat1(tbl, idx, stat) VALUES
			('correlation_pending_operations', 'sqlite_autoindex_correlation_pending_operations_1', '70000 1001 1001 1001 1 1 1 1'),
			('correlation_pending_operations', 'idx_correlation_pending_status', '70000 1001 1001 1001 1001 1 1 1 1'),
			('correlation_pending_operations', 'idx_correlation_pending_exact', '70000 1001 1001 1001 1 1 1 1 1'),
			('correlation_pending_operations', 'idx_correlation_pending_start_event', '70000 1'),
			('correlation_pending_operations', 'idx_correlation_pending_terminal_event', '70000 1001')`,
		`ANALYZE sqlite_schema`,
	} {
		if _, err := store.db.Exec(statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	statement, err := correlationRetentionDeleteStatement(RetentionCorrelationPending)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := store.db.Query(`EXPLAIN QUERY PLAN `+statement, time.Now().UnixNano(), RetentionBatchSize)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan []string
	searched := false
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, detail)
		if strings.HasPrefix(detail, "SCAN correlation_pending_operations") &&
			!strings.Contains(detail, "idx_correlation_pending_retention") {
			t.Errorf("the pending-operation batch scans its table: %q", detail)
		}
		if strings.Contains(detail, "idx_correlation_pending_retention") {
			searched = true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !searched {
		t.Errorf("the pending-operation batch does not use idx_correlation_pending_retention:\n%s", strings.Join(plan, "\n"))
	}
}

// A Secure Client store keeps main's schema: no retention candidate index.
func TestSecureClientStoreKeepsMainsPendingOperationIndexes(t *testing.T) {
	store, err := NewStore(t.TempDir()+"/audit.db", WithSecureClientSchema())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_correlation_pending_retention'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("a Secure Client store got the retention candidate index")
	}
}
