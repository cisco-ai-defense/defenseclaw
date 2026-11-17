// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"testing"
	"time"
)

// rel-1-0-10:GAP-0034: an active cursor protected every edge of its session,
// agent and turn nodes whatever the age, so a session resumed every day kept
// its whole correlation history for as long as it lived. Day retention now
// deletes those edges once they are older than the window; it keeps the edges
// of the cursor's last event and of an open pending operation (what resuming
// the session and finishing the operation need), and the session still
// resumes and records its edges again.
func TestGAP0034LiveSessionEdgesOlderThanTheWindowAreReaped(t *testing.T) {
	store, repo := newCorrelationTestStore(t)
	instance := mustCorrelationInstance(t, repo, "codex", ConnectorCustodyDefenseClaw)
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	old := now.Add(-10 * 24 * time.Hour)
	fresh := now.Add(-time.Hour)
	link := func(tx *CorrelationTx, event CorrelationEvent, kind CorrelationNodeKind, id string, seen time.Time) {
		t.Helper()
		relationship, err := tx.PutRelationship(t.Context(), CorrelationRelationshipInput{
			FromKind: CorrelationNodeSemanticEvent, FromID: string(event.SemanticEventID),
			ToKind: kind, ToID: id, Type: CorrelationBelongsTo,
			Method: CorrelationMethodReported, RuleID: "membership", RuleVersion: "v1",
			Status: CorrelationRelationshipActive, ObservedAt: seen,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.PutRelationshipEvidence(t.Context(), CorrelationRelationshipEvidence{
			RelationshipID: relationship.RelationshipID, SemanticEventID: event.SemanticEventID,
			Role: CorrelationEvidenceSource, Integrity: CorrelationIntegrityVerified, CreatedAt: seen,
		}); err != nil {
			t.Fatal(err)
		}
	}
	// Ten days of history of one live session: every event names the
	// session, the agent and the then-active turn.
	var history []SemanticEventID
	for range 5 {
		event, _ := seedCorrelationEvent(t, repo, instance, correlationSeedOptions{receivedAt: old, mutate: func(tx *CorrelationTx, event CorrelationEvent) {
			link(tx, event, CorrelationNodeSession, "live-session", old)
			link(tx, event, CorrelationNodeAgent, "live-agent", old)
			link(tx, event, CorrelationNodeTurn, "live-turn", old)
		}})
		history = append(history, event.SemanticEventID)
	}
	// The open tool call started ten days ago and is still reported.
	pendingEvent, _ := seedCorrelationEvent(t, repo, instance, correlationSeedOptions{receivedAt: old, mutate: func(tx *CorrelationTx, event CorrelationEvent) {
		link(tx, event, CorrelationNodeSession, "live-session", old)
		if err := tx.PutPendingOperation(t.Context(), CorrelationPendingOperation{
			ConnectorInstanceID: instance.ConnectorInstanceID, Namespace: "codex", Kind: CorrelationIdentifierTool,
			OperationID: "live-tool", Type: CorrelationOperationTool,
			ScopeKind: CorrelationOperationScopeSession, ScopeID: "live-session",
			SessionID: "live-session", TurnID: "live-turn", AgentID: "live-agent",
			StartSemanticEventID: event.SemanticEventID, StartedAt: old,
			Status: CorrelationOperationActive, UpdatedAt: fresh,
		}); err != nil {
			t.Fatal(err)
		}
	}})
	// An old event of the open tool call: its edge to the operation node
	// stays whatever the age (the operation is still open).
	toolEvent, _ := seedCorrelationEvent(t, repo, instance, correlationSeedOptions{receivedAt: old, mutate: func(tx *CorrelationTx, event CorrelationEvent) {
		link(tx, event, CorrelationNodeTool, "live-tool", old)
	}})
	// The session was resumed an hour ago: its cursor is fresh and names
	// that last event, whose edges are also old (first seen ten days ago).
	lastEvent, _ := seedCorrelationEvent(t, repo, instance, correlationSeedOptions{receivedAt: old, mutate: func(tx *CorrelationTx, event CorrelationEvent) {
		link(tx, event, CorrelationNodeSession, "live-session", old)
		if err := tx.PutCursor(t.Context(), CorrelationCursor{
			ConnectorInstanceID: instance.ConnectorInstanceID, SessionID: "live-session", AgentID: "live-agent",
			ActiveTurnID: "live-turn", Phase: "active", Sequence: 40,
			LastSemanticEventID: event.SemanticEventID, ProfileVersion: instance.ProfileVersion,
			Active: true, UpdatedAt: fresh,
		}); err != nil {
			t.Fatal(err)
		}
	}})
	// An edge of the live session inside the window stays.
	recentEvent, _ := seedCorrelationEvent(t, repo, instance, correlationSeedOptions{receivedAt: fresh, mutate: func(tx *CorrelationTx, event CorrelationEvent) {
		link(tx, event, CorrelationNodeSession, "live-session", fresh)
	}})
	if got := countRetentionRows(t, store.db, "correlation_relationships"); got != 19 {
		t.Fatalf("seeded relationships=%d, want 19", got)
	}

	reaper := newRetentionReaperAt(t, store, nil, 7, now, RetentionOptions{}, retentionHooks{yield: noRetentionYield})
	result, err := reaper.Run(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if got := result.RowsDeleted[RetentionCorrelationRelationships]; got != 15 {
		t.Fatalf("deleted relationships=%d, want the 15 history edges older than the window", got)
	}
	for _, event := range []SemanticEventID{lastEvent.SemanticEventID, pendingEvent.SemanticEventID, recentEvent.SemanticEventID, toolEvent.SemanticEventID} {
		if edges := countRelationshipsFrom(t, store, event); edges != 1 {
			t.Fatalf("edge of kept event %s: %d", event, edges)
		}
		if countCorrelationEvent(t, store, event) != 1 {
			t.Fatalf("kept event %s was reaped", event)
		}
	}
	for _, event := range history {
		if edges := countRelationshipsFrom(t, store, event); edges != 0 {
			t.Fatalf("history event %s kept %d edges older than the window", event, edges)
		}
		if countCorrelationEvent(t, store, event) != 0 {
			t.Fatalf("history event %s outlived its edges", event)
		}
	}
	var orphans int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM correlation_relationship_evidence
		WHERE relationship_id NOT IN (SELECT relationship_id FROM correlation_relationships)`).Scan(&orphans); err != nil || orphans != 0 {
		t.Fatalf("evidence outlived its relationships: %d err=%v", orphans, err)
	}

	// The session resumes: its cursor and its open operation are intact,
	// and the next hook records its session edge again.
	cursor, err := repo.FindActiveCursor(t.Context(), instance.ConnectorInstanceID, "live-session")
	if err != nil || cursor.LastSemanticEventID != lastEvent.SemanticEventID || cursor.Sequence != 40 {
		t.Fatalf("resume cursor=%+v err=%v", cursor, err)
	}
	pending, err := repo.ListPendingOperations(t.Context(), CorrelationPendingQuery{
		ConnectorInstanceID: instance.ConnectorInstanceID, Status: CorrelationOperationActive,
	})
	if err != nil || len(pending) != 1 || pending[0].StartSemanticEventID != pendingEvent.SemanticEventID {
		t.Fatalf("open operation after retention=%+v err=%v", pending, err)
	}
	next, _ := seedCorrelationEvent(t, repo, instance, correlationSeedOptions{receivedAt: now, mutate: func(tx *CorrelationTx, event CorrelationEvent) {
		link(tx, event, CorrelationNodeSession, "live-session", now)
		link(tx, event, CorrelationNodeAgent, "live-agent", now)
	}})
	if edges := countRelationshipsFrom(t, store, next.SemanticEventID); edges != 2 {
		t.Fatalf("resumed session recorded %d edges, want 2", edges)
	}
}

// Under the size cap the run cutoff is about an hour ago, but the edges of a
// live session inside the day window are kept, as its cursor is
// (rel-1-0-10:GAP-0034 with issue #1440's size-cap rule).
func TestGAP0034SizeCapKeepsLiveSessionEdgesInsideTheWindow(t *testing.T) {
	store, repo := newCorrelationTestStore(t)
	instance := mustCorrelationInstance(t, repo, "codex", ConnectorCustodyDefenseClaw)
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	link := func(seen time.Time) SemanticEventID {
		event, _ := seedCorrelationEvent(t, repo, instance, correlationSeedOptions{receivedAt: seen, mutate: func(tx *CorrelationTx, event CorrelationEvent) {
			if _, err := tx.PutRelationship(t.Context(), CorrelationRelationshipInput{
				FromKind: CorrelationNodeSemanticEvent, FromID: string(event.SemanticEventID),
				ToKind: CorrelationNodeSession, ToID: "cap-session", Type: CorrelationBelongsTo,
				Method: CorrelationMethodReported, RuleID: "membership", RuleVersion: "v1",
				Status: CorrelationRelationshipActive, ObservedAt: seen,
			}); err != nil {
				t.Fatal(err)
			}
		}})
		return event.SemanticEventID
	}
	inWindow := link(now.Add(-3 * time.Hour))
	otherEvent, _ := seedCorrelationEvent(t, repo, instance, correlationSeedOptions{receivedAt: now.Add(-3 * time.Hour), mutate: func(tx *CorrelationTx, event CorrelationEvent) {
		if _, err := tx.PutRelationship(t.Context(), CorrelationRelationshipInput{
			FromKind: CorrelationNodeSemanticEvent, FromID: string(event.SemanticEventID),
			ToKind: CorrelationNodeSession, ToID: "ended-session", Type: CorrelationBelongsTo,
			Method: CorrelationMethodReported, RuleID: "membership", RuleVersion: "v1",
			Status: CorrelationRelationshipActive, ObservedAt: now.Add(-3 * time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
	}})
	pastWindow := link(now.Add(-8 * 24 * time.Hour))
	seedCorrelationEvent(t, repo, instance, correlationSeedOptions{receivedAt: now, mutate: func(tx *CorrelationTx, event CorrelationEvent) {
		if err := tx.PutCursor(t.Context(), CorrelationCursor{
			ConnectorInstanceID: instance.ConnectorInstanceID, SessionID: "cap-session", AgentID: "cap-agent",
			Phase: "active", Sequence: 3, LastSemanticEventID: event.SemanticEventID,
			ProfileVersion: instance.ProfileVersion, Active: true, UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}})
	reaper := newRetentionReaperAt(t, store, nil, 7, now, RetentionOptions{}, retentionHooks{yield: noRetentionYield})
	var result RetentionRunResult
	result.RowsDeleted = newRetentionCounts()
	if err := reaper.drainCorrelationState(t.Context(), now.Add(-time.Hour), now.Add(-7*24*time.Hour), now, &result); err != nil {
		t.Fatal(err)
	}
	if edges := countRelationshipsFrom(t, store, inWindow); edges != 1 {
		t.Fatalf("size cap took a live session edge inside the window: %d", edges)
	}
	if edges := countRelationshipsFrom(t, store, pastWindow); edges != 0 {
		t.Fatalf("live session edge past the window kept: %d", edges)
	}
	if edges := countRelationshipsFrom(t, store, otherEvent.SemanticEventID); edges != 0 {
		t.Fatalf("size cap kept an edge past its cutoff that touches no live node: %d", edges)
	}
}

func countRelationshipsFrom(t *testing.T, store *Store, event SemanticEventID) int {
	t.Helper()
	var count int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM correlation_relationships
		WHERE from_kind='semantic_event' AND from_id=?`, string(event)).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}
