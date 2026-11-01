// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

// TestRepeatedHookInsertsRunPrepared: a ready store runs the event-history
// and correlation-observation inserts through statements it prepared once,
// in the caller's transaction, and a transaction of another handle still
// runs the text (GAP-1489, GAP-1211).
func TestRepeatedHookInsertsRunPrepared(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	store, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	prepared := store.prepared.Load()
	if prepared == nil {
		t.Fatal("a ready store has no prepared statements")
	}
	for _, query := range []string{eventHistoryInsertSQL, correlationObservationInsertSQL} {
		if (*prepared)[query] == nil {
			t.Errorf("not prepared: %.60s", query)
		}
	}

	insert := `INSERT INTO schema_version (version, applied_at) VALUES (?, '2026-10-26')`
	stmt, err := store.db.Prepare(insert)
	if err != nil {
		t.Fatal(err)
	}
	(*prepared)[insert] = stmt
	ctx := context.Background()
	for _, version := range []int{1001, 1002} {
		tx, err := store.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.txExecPrepared(ctx, tx, "test_insert", insert, version); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("commit after a prepared insert: %v", err)
		}
	}
	var rows int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM schema_version WHERE version IN (1001, 1002)`).Scan(&rows); err != nil || rows != 2 {
		t.Fatalf("prepared inserts committed %d rows, %v", rows, err)
	}

	other, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	tx, err := other.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.txExecPrepared(ctx, tx, "test_insert", insert, 1003); err != nil {
		t.Fatalf("a transaction of another handle: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM schema_version WHERE version = 1003`).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("the other handle's insert committed %d rows, %v", rows, err)
	}
}
