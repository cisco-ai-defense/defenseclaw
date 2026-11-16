// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

// storeWritingBusyObserver writes to the store it observes, as the
// gateway's busy metric does (its correlation observations go to the same
// audit store).
type storeWritingBusyObserver struct {
	store *Store
	done  chan error
}

func (observer *storeWritingBusyObserver) RecordSQLiteBusyMetric(ctx context.Context, _ string) error {
	tx, err := observer.store.db.BeginTx(ctx, nil)
	if err == nil {
		err = tx.Rollback()
	}
	observer.done <- err
	return err
}

// rel-1-0-4 GAP-0944: on a managed RHEL host upgraded from 1.0.2, a hook's
// tool-chain transaction met SQLITE_BUSY, and the busy report, made while the
// transaction still held the store's only connection, waited for that
// connection forever. Every later hook request queued behind it until the
// caller limit answered 429 to fresh native sessions.
func TestTxBusyReportDoesNotWaitForItsOwnTransaction(t *testing.T) {
	store := newV8HistoryStore(t)
	if _, err := store.db.Exec(`CREATE TABLE busy_in_tx_probe (n INTEGER)`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`PRAGMA busy_timeout=0`); err != nil {
		t.Fatal(err)
	}
	contender, err := sql.Open("sqlite", store.DatabasePath()+"?_pragma=busy_timeout(0)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = contender.Close() })
	conn, err := contender.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := conn.ExecContext(t.Context(), `BEGIN IMMEDIATE`); err != nil {
		t.Fatal(err)
	}
	locked := true
	t.Cleanup(func() {
		if locked {
			_, _ = conn.ExecContext(context.Background(), `ROLLBACK`)
		}
	})

	observer := &storeWritingBusyObserver{store: store, done: make(chan error, 1)}
	tx, err := store.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, execErr := txExecContextObserved(t.Context(), tx, "busy_in_tx_probe", observer,
			`INSERT INTO busy_in_tx_probe (n) VALUES (1)`)
		result <- execErr
	}()
	select {
	case execErr := <-result:
		if !isSQLiteBusy(execErr) {
			t.Fatalf("statement under a held write lock = %v, want SQLITE_BUSY", execErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the busy report waited for the connection its own transaction holds")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(t.Context(), `ROLLBACK`); err != nil {
		t.Fatal(err)
	}
	locked = false
	select {
	case err := <-observer.done:
		if err != nil {
			t.Fatalf("busy report after the transaction ended: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the busy report did not run once the transaction let go")
	}
}
