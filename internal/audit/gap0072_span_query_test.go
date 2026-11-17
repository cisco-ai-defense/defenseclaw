// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"strings"
	"testing"
)

// The under-cap check reads the two ends of the rowid, never the whole table
// (review of GAP-0072: MAX(id) - MIN(id) in one SELECT is a full scan).
func TestRejectedRecordsSpanQueryReadsOnlyTheRowidEnds(t *testing.T) {
	store, _ := newRetentionStores(t)
	rows, err := store.db.QueryContext(t.Context(), "EXPLAIN QUERY PLAN "+rejectedRecordsSpanQuery)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close() //nolint:errcheck
	var plan []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(plan) == 0 {
		t.Fatal("no query plan")
	}
	for _, detail := range plan {
		if strings.HasPrefix(strings.TrimSpace(detail), "SCAN") {
			t.Fatalf("span query plan %q scans the table", plan)
		}
	}
}
