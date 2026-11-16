// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

// R109-PERF-WAL review 1: a correlation occurrence whose caller's context
// ended before Commit stores nothing and reports the failure. The grouped
// occurrence of fc449d9be1 committed it and returned success.
func TestR108CanceledCorrelationOccurrenceDoesNotCommit(t *testing.T) {
	store, repo := newCorrelationTestStore(t)
	instance := mustCorrelationInstance(t, repo, "codex", ConnectorCustodyExternal)
	event := receiptAcceptanceEvent(t, instance, CorrelationRailHook, "model_end", time.Now().UTC())
	ctx, cancel := context.WithCancel(t.Context())
	tx, _, err := repo.BeginOccurrence(ctx, CorrelationOccurrenceInput{Event: event})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	cancel()
	if err := tx.Commit(); err == nil {
		t.Error("an occurrence whose caller gave up committed")
	}
	queryCtx, queryCancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer queryCancel()
	var rows int
	if err := store.db.QueryRowContext(queryCtx, `SELECT COUNT(*) FROM correlation_events WHERE semantic_event_id=?`,
		string(event.SemanticEventID)).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Errorf("an occurrence whose caller gave up left %d correlation rows", rows)
	}
}

// R109-PERF-WAL review 1: an occurrence that waits for a busy writer and
// whose caller gives up returns an error and has given back the store's
// lifecycle pin by then, so Store.Close does not wait for work nobody wants.
// The grouped occurrence of fc449d9be1 kept the pin in its leader.
func TestR108CanceledCorrelationOccurrenceReleasesTheStorePin(t *testing.T) {
	store, repo := newCorrelationTestStore(t)
	instance := mustCorrelationInstance(t, repo, "codex", ConnectorCustodyExternal)
	event := receiptAcceptanceEvent(t, instance, CorrelationRailHook, "model_end", time.Now().UTC())
	writer := holdWriterConn(t, store)
	defer writer.Close() //nolint:errcheck
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		tx, _, err := repo.BeginOccurrence(ctx, CorrelationOccurrenceInput{Event: event})
		if err == nil {
			_ = tx.Rollback()
		}
		done <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	// The caller holds the pin while it waits for the writer.
	for store.lifecycleMu.TryLock() {
		store.lifecycleMu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("the occurrence never started waiting for the writer")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Error("an occurrence whose caller gave up returned success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("an occurrence whose caller gave up did not return")
	}
	if !store.lifecycleMu.TryLock() {
		t.Fatal("an occurrence whose caller gave up kept the store lifecycle pin")
	}
	store.lifecycleMu.Unlock()
}

// The same contract for the hook-call write group (callGroupWrite, which
// carries the tool-chain pending action and the receipt mark): a lone write
// whose caller gives up while the writer is busy returns an error, stores
// nothing and has given back the store's lifecycle pin.
func TestR108CanceledCallGroupWriteReleasesTheStorePinAndStoresNothing(t *testing.T) {
	store := newV8HistoryStore(t)
	if _, err := store.db.ExecContext(t.Context(), `CREATE TABLE zz_cancel_probe (id TEXT PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	writer := holdWriterConn(t, store)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- store.callGroupWrite(ctx, func(ctx context.Context, tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `INSERT INTO zz_cancel_probe (id) VALUES ('gone')`)
			return err
		})
	}()
	deadline := time.Now().Add(5 * time.Second)
	// The caller holds the pin while it waits for the writer.
	for store.lifecycleMu.TryLock() {
		store.lifecycleMu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("the write never started waiting for the writer")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Error("a write whose caller gave up returned success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a write whose caller gave up did not return")
	}
	if !store.lifecycleMu.TryLock() {
		t.Fatal("a write whose caller gave up kept the store lifecycle pin")
	}
	store.lifecycleMu.Unlock()
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	var rows int
	if err := store.db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM zz_cancel_probe`).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("stored %d rows (%v) for a write whose caller gave up", rows, err)
	}
}
