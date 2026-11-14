// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"strings"
	"testing"
	"time"
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

// TestPutRelationshipFirstSourceEvidenceRecordsTheFirstOnly: a session edge
// that every hook reports again keeps its first source evidence only, so its
// evidence count stays 1 however long the session runs; a Secure Client
// store keeps main and records every source (S8 GW1, GAP-0621).
func TestPutRelationshipFirstSourceEvidenceRecordsTheFirstOnly(t *testing.T) {
	store, repo := newCorrelationTestStore(t)
	instance := mustCorrelationInstance(t, repo, "claudecode", ConnectorCustodyDefenseClaw)
	at := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	hook := func(i int) (stored bool, count int64) {
		t.Helper()
		seedCorrelationEvent(t, repo, instance, correlationSeedOptions{
			receivedAt: at.Add(time.Duration(i) * time.Second),
			mutate: func(tx *CorrelationTx, event CorrelationEvent) {
				relationship, err := tx.PutRelationship(t.Context(), CorrelationRelationshipInput{
					FromKind: CorrelationNodeAgent, FromID: "agent-1", ToKind: CorrelationNodeSession, ToID: "session-1",
					Type: CorrelationBelongsTo, Method: CorrelationMethodReported, RuleID: "agent-session-membership",
					RuleVersion: "v1", Status: CorrelationRelationshipActive, ObservedAt: event.ReceivedTime,
				})
				if err != nil {
					t.Fatal(err)
				}
				if _, stored, err = tx.PutRelationshipFirstSourceEvidence(t.Context(), CorrelationRelationshipEvidence{
					RelationshipID: relationship.RelationshipID, SemanticEventID: event.SemanticEventID,
					Role: CorrelationEvidenceSource, Integrity: CorrelationIntegrityVerified, CreatedAt: event.ReceivedTime,
				}); err != nil {
					t.Fatal(err)
				}
				if count, err = tx.RelationshipEvidenceCount(t.Context(), relationship.RelationshipID); err != nil {
					t.Fatal(err)
				}
			},
		})
		return stored, count
	}
	for i := range 5 {
		stored, count := hook(i)
		if stored != (i == 0) || count != 1 {
			t.Fatalf("hook %d: stored %v, evidence count %d; want stored only for the first, count 1", i, stored, count)
		}
	}
	store.secureClientSchema = true
	defer func() { store.secureClientSchema = false }()
	if stored, count := hook(5); !stored || count != 2 {
		t.Fatalf("Secure Client store: stored %v, evidence count %d; want every source stored, count 2", stored, count)
	}
}
