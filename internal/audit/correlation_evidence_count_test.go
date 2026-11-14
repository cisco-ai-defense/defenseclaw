// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"strings"
	"testing"
)

// TestCorrelationEvidenceCountReadsNoTableRow: RelationshipEvidenceCount
// runs for every relationship of every hook inside the correlation
// transaction, and the agent and turn membership edges of a session gain one
// evidence row per hook. Its count reads only the relationship index, and
// the implied row is one primary-key lookup, so the writer time of a hook
// does not grow by a table read per earlier hook of its session (S8 GW1).
func TestCorrelationEvidenceCountReadsNoTableRow(t *testing.T) {
	store, _ := newCorrelationTestStore(t)
	for _, plan := range []struct {
		query string
		args  []any
		want  string
	}{
		{correlationEvidenceCountSQL, []any{"rel"}, "USING COVERING INDEX idx_correlation_evidence_relationship"},
		{correlationEvidenceStoredSQL, []any{"ev", "rel"}, "USING INDEX sqlite_autoindex_correlation_relationship_evidence_1 (evidence_id=?)"},
	} {
		rows, err := store.db.Query("EXPLAIN QUERY PLAN "+plan.query, plan.args...)
		if err != nil {
			t.Fatal(err)
		}
		var details []string
		for rows.Next() {
			var id, parent, notUsed int
			var detail string
			if err := rows.Scan(&id, &parent, &notUsed, &detail); err != nil {
				_ = rows.Close()
				t.Fatal(err)
			}
			details = append(details, detail)
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
		if len(details) != 1 || !strings.Contains(details[0], plan.want) {
			t.Fatalf("plan of %q = %q, want one step %q", plan.query, details, plan.want)
		}
	}
}
