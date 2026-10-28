// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

func TestTimeOrderedRecordIDs(t *testing.T) {
	if id := observability.NewTimeOrderedID(); uuid.MustParse(id).Version() != 7 || uuid.MustParse(id).String() != id {
		t.Fatalf("NewTimeOrderedID = %q, want a canonical UUIDv7", id)
	}
	previous := ""
	for range 1000 {
		id, err := observability.TimeOrderedOccurrenceIDs.NewOccurrenceID()
		if err != nil {
			t.Fatal(err)
		}
		if id <= previous {
			t.Fatalf("occurrence ID %q is not after %q", id, previous)
		}
		previous = id
	}
}

// release103CorrelationID is the correlation identifier, relationship and
// evidence ID of DefenseClaw 1.0.3 and every earlier writer (fc6794381d,
// internal/audit/correlation_v8.go), written out here so that a change of
// deterministicCorrelationID fails this test instead of a rollback.
func release103CorrelationID(prefix string, fields ...string) string {
	digest := sha256.New()
	for _, field := range fields {
		_, _ = digest.Write([]byte{0})
		_, _ = digest.Write([]byte(field))
	}
	return prefix + hex.EncodeToString(digest.Sum(nil))
}

// TestCorrelationIDsSurviveARollbackTo103 pins the rollback path (review of
// G-flood-wal: time-ordered correlation IDs broke it). The identifier,
// relationship and evidence rows this build writes for an event with a UUIDv7
// semantic ID carry the IDs that 1.0.3 computes from the same fields. A late
// cross-rail attachment after `defenseclaw rollback` (1.0.3's upserts are this
// file's PutIdentifier, PutRelationship and PutRelationshipEvidence, keyed by
// those IDs) then updates the stored rows: it does not fail on the tables'
// UNIQUE fields and does not add the evidence a second time.
func TestCorrelationIDsSurviveARollbackTo103(t *testing.T) {
	store, repo := newCorrelationTestStore(t)
	instance := mustCorrelationInstance(t, repo, "codex", ConnectorCustodyExternal)
	semantic, err := NewSemanticEventID()
	if err != nil {
		t.Fatal(err)
	}
	if uuid.MustParse(string(semantic)).Version() != 7 {
		t.Fatalf("semantic event ID %s is not a UUIDv7", semantic)
	}
	logical, err := NewSemanticEventID()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	createTx, result, err := repo.BeginOccurrence(t.Context(), CorrelationOccurrenceInput{Event: CorrelationEvent{
		SemanticEventID: semantic, LogicalEventID: LogicalEventID(logical),
		Connector: instance.Connector, ConnectorInstanceID: instance.ConnectorInstanceID,
		Rail: CorrelationRailHook, EventName: "tool.started", ReceivedTime: now,
		ProfileVersion: instance.ProfileVersion, Completeness: CorrelationComplete,
	}})
	if err != nil || result.Status != CorrelationOccurrenceNew {
		t.Fatalf("create result=%+v err=%v", result, err)
	}
	identifier := CorrelationIdentifier{
		SemanticEventID: semantic, ConnectorInstanceID: instance.ConnectorInstanceID, Namespace: "codex.hook",
		Kind: CorrelationIdentifierTool, ValueDigest: correlationDigest("toolu_1"),
		NormalizedValue: "toolu_1", SourceField: "tool_use_id", Origin: CorrelationOriginReported,
		ProfileVersion: instance.ProfileVersion, ObservedAt: now,
	}
	relationship := CorrelationRelationshipInput{
		FromKind: CorrelationNodeSemanticEvent, FromID: string(semantic),
		ToKind: CorrelationNodeTool, ToID: "toolu_1",
		Type: CorrelationBelongsTo, Method: CorrelationMethodReported,
		RuleID: "hook-tool", RuleVersion: "v1", Status: CorrelationRelationshipActive, ObservedAt: now,
	}
	wantIdentifier := release103CorrelationID("id_", string(identifier.ConnectorInstanceID),
		identifier.Namespace, string(identifier.Kind), identifier.ValueDigest, string(identifier.SemanticEventID))
	wantRelationship := release103CorrelationID("rel_", string(relationship.FromKind), relationship.FromID,
		string(relationship.ToKind), relationship.ToID, string(relationship.Type), string(relationship.Method),
		relationship.RuleID, relationship.RuleVersion)
	wantEvidence := release103CorrelationID("ev_", wantRelationship, string(semantic), string(CorrelationEvidenceSource))
	evidence := CorrelationRelationshipEvidence{
		RelationshipID: wantRelationship, SemanticEventID: semantic,
		Role: CorrelationEvidenceSource, Integrity: CorrelationIntegrityVerified, CreatedAt: now,
	}
	put := func(tx *CorrelationTx) (string, CorrelationRelationship, string) {
		t.Helper()
		gotIdentifier, err := tx.PutIdentifier(t.Context(), identifier)
		if err != nil {
			t.Fatal(err)
		}
		gotRelationship, err := tx.PutRelationship(t.Context(), relationship)
		if err != nil {
			t.Fatal(err)
		}
		gotEvidence, err := tx.PutRelationshipEvidence(t.Context(), evidence)
		if err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		return gotIdentifier, gotRelationship, gotEvidence
	}
	gotIdentifier, gotRelationship, gotEvidence := put(createTx)
	if gotIdentifier != wantIdentifier || gotRelationship.RelationshipID != wantRelationship || gotEvidence != wantEvidence {
		t.Fatalf("IDs %s %s %s, want the 1.0.3 IDs %s %s %s", gotIdentifier, gotRelationship.RelationshipID,
			gotEvidence, wantIdentifier, wantRelationship, wantEvidence)
	}

	// The rolled-back writer attaches the same fields again, as a late
	// delivery on another rail does.
	for range 2 {
		tx, _, err := repo.BeginExistingOccurrence(t.Context(), semantic)
		if err != nil {
			t.Fatal(err)
		}
		againIdentifier, againRelationship, againEvidence := put(tx)
		if againIdentifier != wantIdentifier || againRelationship.RelationshipID != wantRelationship ||
			!againRelationship.Unchanged || againEvidence != wantEvidence {
			t.Fatalf("late attachment returned %s %+v %s", againIdentifier, againRelationship, againEvidence)
		}
	}
	for table, want := range map[string]int{
		"correlation_identifiers": 1, "correlation_relationships": 1, "correlation_relationship_evidence": 1,
	} {
		var count int
		if err := store.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != want {
			t.Fatalf("%s has %d rows, want %d", table, count, want)
		}
	}
}

// TestCorrelationLookupsUseUniqueIndexesAfterTheTrim pins that the two
// correlation indexes trimUnreadAuditIndexes drops are not needed: their
// lookups use the unique index with the same leading columns.
func TestCorrelationLookupsUseUniqueIndexesAfterTheTrim(t *testing.T) {
	store, _ := newCorrelationTestStore(t)
	for _, name := range []string{"idx_correlation_identifiers_exact", "idx_correlation_receipts_source"} {
		var count int
		if err := store.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?`, name).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("index %s kept", name)
		}
	}
	plan := func(query string, args ...any) string {
		t.Helper()
		rows, err := store.db.Query(`EXPLAIN QUERY PLAN `+query, args...)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var lines []string
		for rows.Next() {
			var id, parent, unused int
			var detail sql.NullString
			if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
				t.Fatal(err)
			}
			lines = append(lines, detail.String)
		}
		return strings.Join(lines, "; ")
	}
	for _, check := range []struct{ query, index string }{
		{`SELECT event.semantic_event_id FROM correlation_identifiers AS identifier
			JOIN correlation_events AS event ON event.semantic_event_id=identifier.semantic_event_id
			WHERE identifier.connector_instance_id='c' AND ((identifier.namespace='n' AND identifier.identifier_kind='session' AND identifier.value_digest='d')
			OR (identifier.namespace='n' AND identifier.identifier_kind='tool_invocation' AND identifier.value_digest='e')) LIMIT 1`,
			"sqlite_autoindex_correlation_identifiers_2"},
		{`SELECT semantic_event_id FROM correlation_receipts
			WHERE connector_instance_id='c' AND source_key_digest='d' AND fingerprint_sha256<>'f'
			ORDER BY first_received_time_unix_nano, semantic_event_id LIMIT 1`,
			"sqlite_autoindex_correlation_receipts_1"},
	} {
		got := plan(check.query)
		if !strings.Contains(got, check.index) {
			t.Fatalf("plan %q does not use %s", got, check.index)
		}
	}
}
