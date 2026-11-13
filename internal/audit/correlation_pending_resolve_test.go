// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"errors"
	"testing"
	"time"
)

// TestResolvePendingOperationDeletesTheEndedOperation: resolving an
// operation whose ID no other scope holds deletes it, the same end again
// finds nothing (ErrCorrelationNotFound, which every caller ignores), and an
// operation a 1.0.9 binary ended is still found stale (S8 R5).
func TestResolvePendingOperationDeletesTheEndedOperation(t *testing.T) {
	store, repo := newCorrelationTestStore(t)
	instance := mustCorrelationInstance(t, repo, "codex", ConnectorCustodyDefenseClaw)
	now := time.Now().UTC()
	locator := func(id string) CorrelationPendingLocator {
		return CorrelationPendingLocator{
			ConnectorInstanceID: instance.ConnectorInstanceID, Namespace: "codex", Kind: CorrelationIdentifierTool,
			OperationID: id, Type: CorrelationOperationTool,
			ScopeKind: CorrelationOperationScopeSession, ScopeID: "session-a",
		}
	}
	for _, id := range []string{"tool-open", "tool-ended-by-1.0.9"} {
		seedCorrelationEvent(t, repo, instance, correlationSeedOptions{receivedAt: now, mutate: func(tx *CorrelationTx, event CorrelationEvent) {
			if err := tx.PutPendingOperation(t.Context(), CorrelationPendingOperation{
				ConnectorInstanceID: instance.ConnectorInstanceID, Namespace: "codex", Kind: CorrelationIdentifierTool,
				OperationID: id, Type: CorrelationOperationTool,
				ScopeKind: CorrelationOperationScopeSession, ScopeID: "session-a", SessionID: "session-a",
				StartSemanticEventID: event.SemanticEventID, StartedAt: now,
				Status: CorrelationOperationActive, UpdatedAt: now,
			}); err != nil {
				t.Error(err)
			}
		}})
	}
	var results []error
	seedCorrelationEvent(t, repo, instance, correlationSeedOptions{receivedAt: now.Add(time.Second), eventName: "tool.completed",
		mutate: func(tx *CorrelationTx, event CorrelationEvent) {
			// What a 1.0.9 binary did: mark the operation ended.
			if _, err := tx.tx.ExecContext(t.Context(), correlationPendingMarkResolvedSQL,
				string(event.SemanticEventID), unixNano(event.ReceivedTime), string(CorrelationOperationCompleted),
				unixNano(event.ReceivedTime), string(instance.ConnectorInstanceID), "codex",
				string(CorrelationIdentifierTool), "tool-ended-by-1.0.9", string(CorrelationOperationTool),
				string(CorrelationOperationScopeSession), "session-a"); err != nil {
				t.Error(err)
			}
			for _, id := range []string{"tool-open", "tool-open", "tool-ended-by-1.0.9"} {
				results = append(results, tx.ResolvePendingOperation(t.Context(), locator(id),
					event.SemanticEventID, CorrelationOperationCompleted, event.ReceivedTime))
			}
		}})
	if len(results) != 3 || results[0] != nil || !errors.Is(results[1], ErrCorrelationNotFound) ||
		!errors.Is(results[2], ErrCorrelationStale) {
		t.Fatalf("resolve results %v, want nil, not found, stale", results)
	}
	var open, ended int
	if err := store.db.QueryRow(`SELECT
		COUNT(CASE WHEN operation_id='tool-open' THEN 1 END),
		COUNT(CASE WHEN operation_id='tool-ended-by-1.0.9' AND status='completed' THEN 1 END)
		FROM correlation_pending_operations`).Scan(&open, &ended); err != nil {
		t.Fatal(err)
	}
	if open != 0 || ended != 1 {
		t.Fatalf("pending rows: resolved %d (want 0), 1.0.9 ended %d (want 1)", open, ended)
	}
}
