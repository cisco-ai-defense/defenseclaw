// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"testing"
	"time"
)

func TestCorrelationRetentionIsBoundedGraphAwareAndPreservesActiveState(t *testing.T) {
	store, repo := newCorrelationTestStore(t)
	instance := mustCorrelationInstance(t, repo, "codex", ConnectorCustodyDefenseClaw)
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	old := now.Add(-91 * 24 * time.Hour)

	activeCursorEvent, _ := seedCorrelationEvent(t, repo, instance, correlationSeedOptions{receivedAt: old, mutate: func(tx *CorrelationTx, event CorrelationEvent) {
		if err := tx.PutCursor(t.Context(), CorrelationCursor{
			ConnectorInstanceID: instance.ConnectorInstanceID, SessionID: "active-session", AgentID: "active-agent",
			ActiveTurnID: "active-turn", Phase: "active", Sequence: 7,
			LastSemanticEventID: event.SemanticEventID, ProfileVersion: instance.ProfileVersion,
			Active: true, UpdatedAt: old,
		}); err != nil {
			t.Fatal(err)
		}
		relationship, err := tx.PutRelationship(t.Context(), CorrelationRelationshipInput{
			FromKind: CorrelationNodeSemanticEvent, FromID: string(event.SemanticEventID),
			ToKind: CorrelationNodeTurn, ToID: "active-turn", Type: CorrelationBelongsTo,
			Method: CorrelationMethodReported, RuleID: "active-fixture", RuleVersion: "v1",
			Status: CorrelationRelationshipActive, ObservedAt: old,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.PutRelationshipEvidence(t.Context(), CorrelationRelationshipEvidence{
			RelationshipID: relationship.RelationshipID, SemanticEventID: event.SemanticEventID,
			Role: CorrelationEvidenceSource, Integrity: CorrelationIntegrityVerified, CreatedAt: old,
		}); err != nil {
			t.Fatal(err)
		}
	}})
	activePendingEvent, _ := seedCorrelationEvent(t, repo, instance, correlationSeedOptions{receivedAt: old, mutate: func(tx *CorrelationTx, event CorrelationEvent) {
		if err := tx.PutPendingOperation(t.Context(), CorrelationPendingOperation{
			ConnectorInstanceID: instance.ConnectorInstanceID, Namespace: "codex", Kind: CorrelationIdentifierTool,
			OperationID: "active-tool", Type: CorrelationOperationTool,
			ScopeKind: CorrelationOperationScopeSession, ScopeID: "active-session",
			SessionID: "active-session", TurnID: "active-turn",
			StartSemanticEventID: event.SemanticEventID, StartedAt: old,
			Status: CorrelationOperationActive, UpdatedAt: old,
		}); err != nil {
			t.Fatal(err)
		}
	}})
	unexpiredReceiptEvent, _ := seedCorrelationEvent(t, repo, instance, correlationSeedOptions{receivedAt: old, receipt: &CorrelationReceiptClaim{
		SourceKeyDigest: correlationDigest("unexpired-source"), FingerprintSHA256: correlationDigest("unexpired-payload"),
		ReceivedAt: old, ExpiresAt: now.Add(time.Hour),
	}})
	orphanEvent, _ := seedCorrelationEvent(t, repo, instance, correlationSeedOptions{receivedAt: old})
	expiredReceiptEvent, _ := seedCorrelationEvent(t, repo, instance, correlationSeedOptions{receivedAt: old, receipt: &CorrelationReceiptClaim{
		SourceKeyDigest: correlationDigest("expired-source"), FingerprintSHA256: correlationDigest("expired-payload"),
		ReceivedAt: old, ExpiresAt: old.Add(time.Hour),
	}})

	reaper := newRetentionReaperAt(t, store, nil, 90, now, RetentionOptions{}, retentionHooks{})
	result, err := reaper.Run(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if result.RowsDeleted[RetentionCorrelationReceipts] != 1 ||
		result.RowsDeleted[RetentionCorrelationEvents] < 2 {
		t.Fatalf("correlation retention counts=%+v", result.RowsDeleted)
	}
	for _, eventID := range []SemanticEventID{
		activeCursorEvent.SemanticEventID, activePendingEvent.SemanticEventID, unexpiredReceiptEvent.SemanticEventID,
	} {
		if countCorrelationEvent(t, store, eventID) != 1 {
			t.Fatalf("protected correlation event %s was reaped", eventID)
		}
	}
	for _, eventID := range []SemanticEventID{orphanEvent.SemanticEventID, expiredReceiptEvent.SemanticEventID} {
		if countCorrelationEvent(t, store, eventID) != 0 {
			t.Fatalf("unreferenced old correlation event %s survived", eventID)
		}
	}
	for _, table := range []string{"correlation_connector_instances", "correlation_cursors",
		"correlation_pending_operations", "correlation_relationships", "correlation_relationship_evidence"} {
		if countRetentionRows(t, store.db, table) == 0 {
			t.Fatalf("active/protected table %s was emptied", table)
		}
	}
	if _, err := repo.GetConnectorInstance(t.Context(), instance.ConnectorInstanceID); err != nil {
		t.Fatalf("connector instance was reaped: %v", err)
	}
}

func countCorrelationEvent(t *testing.T, store *Store, semantic SemanticEventID) int {
	t.Helper()
	var count int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM correlation_events WHERE semantic_event_id=?`, string(semantic)).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}
