// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// pendingResolveFixture is one connector instance whose tool operations of
// one provider ID can be started and resolved per session.
type pendingResolveFixture struct {
	t        *testing.T
	store    *Store
	repo     *CorrelationRepository
	instance ConnectorInstance
	at       time.Time
}

func newPendingResolveFixture(t *testing.T, store *Store, repo *CorrelationRepository) *pendingResolveFixture {
	return &pendingResolveFixture{t: t, store: store, repo: repo,
		instance: mustCorrelationInstance(t, repo, "codex", ConnectorCustodyDefenseClaw), at: time.Now().UTC()}
}

func (fixture *pendingResolveFixture) locator(id, session string) CorrelationPendingLocator {
	return CorrelationPendingLocator{
		ConnectorInstanceID: fixture.instance.ConnectorInstanceID, Namespace: "codex", Kind: CorrelationIdentifierTool,
		OperationID: id, Type: CorrelationOperationTool,
		ScopeKind: CorrelationOperationScopeSession, ScopeID: session,
	}
}

func (fixture *pendingResolveFixture) start(id, session string) {
	t := fixture.t
	t.Helper()
	fixture.at = fixture.at.Add(time.Millisecond)
	seedCorrelationEvent(t, fixture.repo, fixture.instance, correlationSeedOptions{receivedAt: fixture.at,
		mutate: func(tx *CorrelationTx, event CorrelationEvent) {
			if err := tx.PutPendingOperation(t.Context(), CorrelationPendingOperation{
				ConnectorInstanceID: fixture.instance.ConnectorInstanceID, Namespace: "codex",
				Kind: CorrelationIdentifierTool, OperationID: id, Type: CorrelationOperationTool,
				ScopeKind: CorrelationOperationScopeSession, ScopeID: session, SessionID: session,
				StartSemanticEventID: event.SemanticEventID, StartedAt: fixture.at,
				Status: CorrelationOperationActive, UpdatedAt: fixture.at,
			}); err != nil {
				t.Error(err)
			}
		}})
}

// resolve ends the operation id of session in a new terminal event and
// returns the result. A raw mark, the way a 1.0.9 binary ended it, is
// applied first when markedBy109 is set.
func (fixture *pendingResolveFixture) resolve(id, session string, markedBy109 bool) error {
	t := fixture.t
	t.Helper()
	fixture.at = fixture.at.Add(time.Millisecond)
	var result error
	seedCorrelationEvent(t, fixture.repo, fixture.instance, correlationSeedOptions{
		receivedAt: fixture.at, eventName: "tool.completed",
		mutate: func(tx *CorrelationTx, event CorrelationEvent) {
			if markedBy109 {
				args := append([]any{string(event.SemanticEventID), unixNano(fixture.at),
					string(CorrelationOperationCompleted), unixNano(fixture.at)},
					pendingLocatorKeyForTest(fixture.locator(id, session))...)
				if _, err := tx.tx.ExecContext(t.Context(), correlationPendingMarkResolvedSQL, args...); err != nil {
					t.Error(err)
				}
			}
			result = tx.ResolvePendingOperation(t.Context(), fixture.locator(id, session),
				event.SemanticEventID, CorrelationOperationCompleted, fixture.at)
		}})
	return result
}

func (fixture *pendingResolveFixture) rows(id, session, status string) int {
	t := fixture.t
	t.Helper()
	var count int
	if err := fixture.store.db.QueryRow(`SELECT COUNT(*) FROM correlation_pending_operations
		WHERE operation_id=? AND scope_id=? AND status=?`, id, session, status).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func pendingLocatorKeyForTest(locator CorrelationPendingLocator) []any {
	return []any{string(locator.ConnectorInstanceID), locator.Namespace, string(locator.Kind),
		locator.OperationID, string(locator.Type), string(locator.ScopeKind), locator.ScopeID}
}

// TestResolvePendingOperationDeletesTheEndedOperation: resolving deletes
// the operation; the same end again is not found (every caller ignores
// that), and so is a late end of a provider ID another session reuses, in
// either order, while that session's operation stays active; an operation
// a 1.0.9 binary ended is still found stale (S8 R5).
func TestResolvePendingOperationDeletesTheEndedOperation(t *testing.T) {
	store, repo := newCorrelationTestStore(t)
	fixture := newPendingResolveFixture(t, store, repo)

	fixture.start("tool-1", "session-a")
	if err := fixture.resolve("tool-1", "session-a", false); err != nil {
		t.Fatalf("resolve = %v", err)
	}
	if err := fixture.resolve("tool-1", "session-a", false); !errors.Is(err, ErrCorrelationNotFound) {
		t.Fatalf("second resolve = %v, want not found", err)
	}
	if got := fixture.rows("tool-1", "session-a", "active") + fixture.rows("tool-1", "session-a", "completed"); got != 0 {
		t.Fatalf("resolved operation kept %d rows", got)
	}

	// The ID reused: session b starts it after session a ended its own.
	fixture.start("tool-1", "session-b")
	if err := fixture.resolve("tool-1", "session-a", false); !errors.Is(err, ErrCorrelationNotFound) {
		t.Fatalf("late end of session a after session b started = %v, want not found", err)
	}
	// Both open, session a ends, then its end comes again.
	fixture.start("tool-1", "session-a")
	if err := fixture.resolve("tool-1", "session-a", false); err != nil {
		t.Fatalf("resolve while session b holds the ID = %v", err)
	}
	if err := fixture.resolve("tool-1", "session-a", false); !errors.Is(err, ErrCorrelationNotFound) {
		t.Fatalf("second end of session a while session b holds the ID = %v, want not found", err)
	}
	if got := fixture.rows("tool-1", "session-b", "active"); got != 1 {
		t.Fatalf("session b's operation: %d active rows, want 1", got)
	}

	fixture.start("tool-2", "session-a")
	if err := fixture.resolve("tool-2", "session-a", true); !errors.Is(err, ErrCorrelationStale) {
		t.Fatalf("resolve of an operation 1.0.9 ended = %v, want stale", err)
	}
	if got := fixture.rows("tool-2", "session-a", "completed"); got != 1 {
		t.Fatalf("the operation 1.0.9 ended: %d completed rows, want 1", got)
	}
}

// TestSecureClientResolvePendingOperationKeepsMainsState: a Secure Client
// store marks the operation ended as main does, finds the same end again
// stale, and reports an operation of the ID in another scope only as a
// conflict.
func TestSecureClientResolvePendingOperationKeepsMainsState(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"), WithSecureClientSchema())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	repo, err := store.CorrelationRepository()
	if err != nil {
		t.Fatal(err)
	}
	fixture := newPendingResolveFixture(t, store, repo)
	fixture.start("tool-1", "session-a")
	fixture.start("tool-1", "session-b")
	if err := fixture.resolve("tool-1", "session-a", false); err != nil {
		t.Fatalf("resolve = %v", err)
	}
	if got := fixture.rows("tool-1", "session-a", "completed"); got != 1 {
		t.Fatalf("Secure Client ended operation: %d completed rows, want 1", got)
	}
	if err := fixture.resolve("tool-1", "session-a", false); !errors.Is(err, ErrCorrelationStale) {
		t.Fatalf("second resolve = %v, want stale", err)
	}
	if err := fixture.resolve("tool-1", "session-c", false); !errors.Is(err, ErrCorrelationConflict) {
		t.Fatalf("resolve in a scope without the operation = %v, want conflict", err)
	}
}
