// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"encoding/json"
	"sort"
	"testing"
	"time"
)

// seedImpliedEvidenceGraph writes one occurrence at at with the edges the
// gateway writes: a semantic event -> session edge with the occurrence as
// its source, a turn -> session edge with the occurrence as its source, and
// a semantic event -> trace edge with the occurrence as its source and a
// record as corroborating evidence. tag prefixes the rule IDs.
func seedImpliedEvidenceGraph(
	t *testing.T,
	repo *CorrelationRepository,
	instance ConnectorInstance,
	at time.Time,
	tag string,
	receipt *CorrelationReceiptClaim,
) CorrelationEvent {
	t.Helper()
	ctx := t.Context()
	event, _ := seedCorrelationEvent(t, repo, instance, correlationSeedOptions{
		receivedAt: at, receipt: receipt,
		mutate: func(tx *CorrelationTx, event CorrelationEvent) {
			if err := tx.PutObservation(ctx, CorrelationObservation{
				RecordID: tag + "-record", SemanticEventID: event.SemanticEventID,
				Signal: CorrelationSignalLogs, Bucket: "agent", EventName: "tool.started",
				ObservedAt: at, Status: CorrelationObservationExportEligible,
			}); err != nil {
				t.Fatal(err)
			}
			for _, edge := range []struct {
				fromKind CorrelationNodeKind
				fromID   string
				toKind   CorrelationNodeKind
				toID     string
				rule     string
				record   bool
			}{
				{CorrelationNodeSemanticEvent, string(event.SemanticEventID), CorrelationNodeSession, tag + "-session", tag + "-event-session", false},
				{CorrelationNodeTurn, tag + "-turn", CorrelationNodeSession, tag + "-session", tag + "-turn-session", false},
				{CorrelationNodeSemanticEvent, string(event.SemanticEventID), CorrelationNodeTrace, tag + "-trace", tag + "-event-trace", true},
			} {
				relationship, err := tx.PutRelationship(ctx, CorrelationRelationshipInput{
					FromKind: edge.fromKind, FromID: edge.fromID, ToKind: edge.toKind, ToID: edge.toID,
					Type: CorrelationBelongsTo, Method: CorrelationMethodReported, RuleID: edge.rule,
					RuleVersion: "v1", Status: CorrelationRelationshipActive, ObservedAt: at,
				})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := tx.PutRelationshipEvidence(ctx, CorrelationRelationshipEvidence{
					RelationshipID: relationship.RelationshipID, SemanticEventID: event.SemanticEventID,
					Role: CorrelationEvidenceSource, Integrity: CorrelationIntegrityVerified, CreatedAt: at,
				}); err != nil {
					t.Fatal(err)
				}
				if edge.record {
					if _, err := tx.PutRelationshipEvidence(ctx, CorrelationRelationshipEvidence{
						RelationshipID: relationship.RelationshipID, RecordID: tag + "-record",
						Role: CorrelationEvidenceCorroborating, Integrity: CorrelationIntegrityVerified,
						CreatedAt: at.Add(time.Millisecond),
					}); err != nil {
						t.Fatal(err)
					}
				}
			}
		},
	})
	return event
}

// storeImpliedEvidenceRows writes the implied evidence rows the way a 1.0.9
// binary stored them.
func storeImpliedEvidenceRows(t *testing.T, store *Store) {
	t.Helper()
	rows, err := store.db.Query(`SELECT relationship_id, from_kind, from_id, created_time_unix_nano
		FROM correlation_relationships`)
	if err != nil {
		t.Fatal(err)
	}
	var implied []CorrelationRelationshipEvidence
	for rows.Next() {
		var relationship CorrelationRelationship
		var created int64
		if err := rows.Scan(&relationship.RelationshipID, &relationship.FromKind, &relationship.FromID, &created); err != nil {
			t.Fatal(err)
		}
		relationship.CreatedAt = time.Unix(0, created).UTC()
		if evidence, ok := impliedCorrelationEvidence(relationship); ok {
			implied = append(implied, evidence)
		}
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	for _, evidence := range implied {
		if _, err := store.db.Exec(`INSERT INTO correlation_relationship_evidence (
			evidence_id, relationship_id, evidence_record_id, semantic_event_id, evidence_role,
			integrity_state, created_time_unix_nano) VALUES (?, ?, NULL, ?, ?, ?, ?)`,
			evidence.EvidenceID, evidence.RelationshipID, string(evidence.SemanticEventID),
			string(evidence.Role), string(evidence.Integrity), unixNano(evidence.CreatedAt)); err != nil {
			t.Fatal(err)
		}
	}
}

// TestImpliedCorrelationEvidenceIsTheRowItReplaces: the source evidence of
// an edge from a semantic event is no longer stored, and QueryGraph and the
// exported evidence counts are byte for byte what they were with the stored
// row (S8 R5).
func TestImpliedCorrelationEvidenceIsTheRowItReplaces(t *testing.T) {
	store, repo := newCorrelationTestStore(t)
	instance := mustCorrelationInstance(t, repo, "codex", ConnectorCustodyDefenseClaw)
	at := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	event := seedImpliedEvidenceGraph(t, repo, instance, at, "g", nil)
	// The turn edge's source and the trace edge's record stay stored.
	if got := countRetentionRows(t, store.db, "correlation_relationship_evidence"); got != 2 {
		t.Fatalf("%d evidence rows stored, want 2", got)
	}
	snapshot := func() (string, map[string]int64) {
		t.Helper()
		graph, err := repo.QueryGraph(t.Context(), CorrelationGraphQuery{
			Anchor: CorrelationAnchor{SemanticEventID: event.SemanticEventID},
		})
		if err != nil {
			t.Fatal(err)
		}
		// The event's two edges; the turn's edge is not on the event.
		if len(graph.Relationships) != 2 || len(graph.Evidence) != 3 {
			t.Fatalf("graph has %d relationships and %d evidence rows, want 2 and 3",
				len(graph.Relationships), len(graph.Evidence))
		}
		graph.AsOf = time.Time{}
		encoded, err := json.Marshal(graph)
		if err != nil {
			t.Fatal(err)
		}
		tx, _, err := repo.BeginExistingOccurrence(t.Context(), event.SemanticEventID)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback() //nolint:errcheck
		counts := map[string]int64{}
		for _, relationship := range graph.Relationships {
			count, err := tx.RelationshipEvidenceCount(t.Context(), relationship.RelationshipID)
			if err != nil {
				t.Fatal(err)
			}
			counts[relationship.RuleID] = count
		}
		return string(encoded), counts
	}
	implied, impliedCounts := snapshot()
	if want := map[string]int64{"g-event-session": 1, "g-event-trace": 2}; len(impliedCounts) != len(want) ||
		impliedCounts["g-event-session"] != 1 || impliedCounts["g-event-trace"] != 2 {
		t.Fatalf("evidence counts %v, want %v", impliedCounts, want)
	}
	storeImpliedEvidenceRows(t, store)
	if got := countRetentionRows(t, store.db, "correlation_relationship_evidence"); got != 4 {
		t.Fatalf("%d evidence rows with the 1.0.9 rows, want 4", got)
	}
	stored, storedCounts := snapshot()
	if stored != implied {
		t.Fatalf("QueryGraph differs with the stored rows:\nimplied %s\nstored  %s", implied, stored)
	}
	for rule, count := range storedCounts {
		if impliedCounts[rule] != count {
			t.Fatalf("%s evidence count %d with the stored rows, %d without", rule, count, impliedCounts[rule])
		}
	}
}

// TestRetentionReapsTheSameGraphWithImpliedEvidence: retention keeps and
// removes the same events and edges whether the implied evidence rows are
// stored (a 1.0.9 store) or not.
func TestRetentionReapsTheSameGraphWithImpliedEvidence(t *testing.T) {
	survivors := func(storeRows bool) []string {
		store, repo := newCorrelationTestStore(t)
		instance := mustCorrelationInstance(t, repo, "codex", ConnectorCustodyDefenseClaw)
		now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
		old := now.Add(-91 * 24 * time.Hour)
		reaped := seedImpliedEvidenceGraph(t, repo, instance, old, "reaped", nil)
		kept := seedImpliedEvidenceGraph(t, repo, instance, old, "kept", &CorrelationReceiptClaim{
			SourceKeyDigest: correlationDigest("kept-source"), FingerprintSHA256: correlationDigest("kept-payload"),
			ReceivedAt: old, ExpiresAt: now.Add(time.Hour),
		})
		if storeRows {
			storeImpliedEvidenceRows(t, store)
		}
		reaper := newRetentionReaperAt(t, store, nil, 90, now, RetentionOptions{}, retentionHooks{})
		if _, err := reaper.Run(t.Context()); err != nil {
			t.Fatal(err)
		}
		var result []string
		for name, event := range map[string]CorrelationEvent{"reaped": reaped, "kept": kept} {
			if countCorrelationEvent(t, store, event.SemanticEventID) == 1 {
				result = append(result, "event "+name)
			}
		}
		rows, err := store.db.Query(`SELECT rule_id FROM correlation_relationships`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		for rows.Next() {
			var rule string
			if err := rows.Scan(&rule); err != nil {
				t.Fatal(err)
			}
			result = append(result, "edge "+rule)
		}
		sort.Strings(result)
		return result
	}
	without, with := survivors(false), survivors(true)
	if len(without) == 0 {
		t.Fatal("retention kept nothing; the protected occurrence is not protected")
	}
	if encodedWithout, encodedWith := jsonForTest(t, without), jsonForTest(t, with); encodedWithout != encodedWith {
		t.Fatalf("retention kept %s without the stored rows, %s with them", encodedWithout, encodedWith)
	}
	for _, survivor := range without {
		if survivor == "event reaped" {
			t.Fatalf("an unprotected old occurrence survived: %v", without)
		}
	}
}

func jsonForTest(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
