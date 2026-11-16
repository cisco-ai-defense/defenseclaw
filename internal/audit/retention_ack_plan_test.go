// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"strings"
	"testing"
)

// GAP-1790: the legacy ACK baseline statements of an audit retention batch
// must start from the batch's candidate set and look audit rows up by id.
// Driven from audit_events they read the whole id index (or every bucket-less
// row) inside the retention transaction; on a 3 GB store with a cold page
// cache that held the writer about 3.5 s, and the hooks queued behind it after
// a gateway start were closed as a gateway no-answer.
func TestRetentionACKBaselinesStartFromTheCandidateBatch(t *testing.T) {
	store, _ := newRetentionStores(t)
	for _, statement := range []string{
		`CREATE TEMP TABLE IF NOT EXISTS retention_v8_audit_candidates (id TEXT PRIMARY KEY) WITHOUT ROWID`,
		`ANALYZE`,
		// A grown store: millions of audit rows, almost none ACK baselines.
		`DELETE FROM sqlite_stat1 WHERE tbl IN ('audit_events', 'alert_acknowledgement_baselines')`,
		`INSERT INTO sqlite_stat1(tbl, idx, stat) VALUES
			('audit_events', 'sqlite_autoindex_audit_events_1', '3000000 1'),
			('audit_events', 'idx_audit_bucket_timestamp', '3000000 3000000 1'),
			('audit_events', 'idx_retention_audit_events_timestamp', '3000000 1 1'),
			('alert_acknowledgement_baselines', 'sqlite_autoindex_alert_acknowledgement_baselines_1', '1 1')`,
		`ANALYZE sqlite_schema`,
	} {
		if _, err := store.db.Exec(statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	for name, statement := range map[string]string{
		"baseline":   retentionACKBaselineInsert("?,?"),
		"projection": retentionACKProjectionInsert,
	} {
		args := []any{"2026-10-28T00:00:00Z"}
		if name == "baseline" {
			args = append(args, "a", "b")
		}
		rows, err := store.db.Query(`EXPLAIN QUERY PLAN `+statement, args...)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
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
		rows.Close()
		if len(plan) == 0 || !strings.HasPrefix(plan[0], "SCAN candidate") {
			t.Errorf("%s statement does not start from the candidate batch:\n%s", name, strings.Join(plan, "\n"))
		}
		for _, detail := range plan {
			if strings.HasPrefix(detail, "SCAN event") || strings.HasPrefix(detail, "SCAN TABLE audit_events") ||
				(strings.Contains(detail, " event ") && !strings.Contains(detail, "(id=?)")) {
				t.Errorf("%s statement reads audit_events other than by id: %q", name, detail)
			}
		}
	}
}
