// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"errors"
	"testing"
	"time"
)

func countCorrelationEvents(t *testing.T, store *Store, events ...CorrelationEvent) int {
	t.Helper()
	total := 0
	for _, event := range events {
		var n int
		if err := store.db.QueryRow(`SELECT COUNT(*) FROM correlation_events WHERE semantic_event_id = ?`,
			string(event.SemanticEventID)).Scan(&n); err != nil {
			t.Fatal(err)
		}
		total += n
	}
	return total
}

func waitOccurrenceGroup(t *testing.T, store *Store, want int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		store.occurrenceGroup.mu.Lock()
		active, pending := store.occurrenceGroup.active, len(store.occurrenceGroup.pending)
		store.occurrenceGroup.mu.Unlock()
		if active && pending == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("queued occurrences behind a running leader never reached %d", want)
}

// r108 SWEEP-100: occurrences queued behind a busy writer share one
// transaction. Each caller drives its own occurrence; one that rolls back
// loses only its own rows, and the others commit.
func TestR108CorrelationOccurrencesShareOneTransaction(t *testing.T) {
	store, repo := newCorrelationTestStore(t)
	instance := mustCorrelationInstance(t, repo, "codex", ConnectorCustodyExternal)
	now := time.Now().UTC()
	conn := holdWriterConn(t, store)
	const callers = 4
	events := make([]CorrelationEvent, callers)
	errs := make(chan error, callers)
	for index := range callers {
		events[index] = receiptAcceptanceEvent(t, instance, CorrelationRailHook, "model_end", now)
		go func() {
			tx, _, err := repo.BeginOccurrence(t.Context(), CorrelationOccurrenceInput{Event: events[index]})
			if err != nil {
				errs <- err
				return
			}
			defer tx.Rollback() //nolint:errcheck
			if index == 2 {
				errs <- tx.Rollback()
				return
			}
			errs <- tx.Commit()
		}()
		if index == 0 {
			waitOccurrenceGroup(t, store, 0)
		}
	}
	waitOccurrenceGroup(t, store, callers-1)
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	for range callers {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	for index, event := range events {
		want := 1
		if index == 2 {
			want = 0
		}
		if got := countCorrelationEvents(t, store, event); got != want {
			t.Errorf("occurrence %d: %d rows, want %d", index, got, want)
		}
	}
}

// An occurrence whose caller's context ends while it waits for its turn
// returns at once with that error and writes nothing, while the writer is
// still held (the observe-mode ledger bound, rel-1-0-6 GAP-0152).
func TestR108CorrelationOccurrenceWaitEndsWithItsContext(t *testing.T) {
	store, repo := newCorrelationTestStore(t)
	instance := mustCorrelationInstance(t, repo, "codex", ConnectorCustodyExternal)
	now := time.Now().UTC()
	conn := holdWriterConn(t, store)
	leader := receiptAcceptanceEvent(t, instance, CorrelationRailHook, "model_end", now)
	leaderDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		tx, _, err := repo.BeginOccurrence(ctx, CorrelationOccurrenceInput{Event: leader})
		if err == nil {
			err = tx.Rollback()
		}
		leaderDone <- err
	}()
	waitOccurrenceGroup(t, store, 0)
	late := receiptAcceptanceEvent(t, instance, CorrelationRailHook, "model_end", now)
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, _, err := repo.BeginOccurrence(ctx, CorrelationOccurrenceInput{Event: late})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the caller's deadline", err)
	}
	if waited := time.Since(started); waited > 2*time.Second {
		t.Fatalf("a caller whose context ended waited %v for the busy writer", waited)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-leaderDone; err != nil {
		t.Fatal(err)
	}
	if got := countCorrelationEvents(t, store, leader, late); got != 0 {
		t.Fatalf("%d rows stored by rolled-back and abandoned occurrences", got)
	}
}
