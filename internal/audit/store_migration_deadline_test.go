// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A migration that stalls inside SQLite (GAP-0664: a loaded -race run sat
// 50 minutes in the scan_findings ALTER) must end Init with an error instead
// of blocking it for ever. The query below never finishes on its own; only
// the migration deadline reaching SQLite stops it.
func TestApplyMigrationStopsAStalledStatementAtTheDeadline(t *testing.T) {
	store, err := NewStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	shortMigrationLimit(store, 200*time.Millisecond)
	stalled := migration{description: "test: a statement that never finishes", apply: func(ex dbExecer) error {
		var n int64
		return ex.QueryRow("WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c) SELECT count(*) FROM c").Scan(&n)
	}}

	done := make(chan error, 1)
	go func() { done <- store.applyMigration(1, stalled) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a stalled migration returned no error")
		}
		if !errors.Is(err, context.DeadlineExceeded) && !isInterrupted(err) {
			t.Fatalf("stalled migration error is not the deadline: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("a stalled migration was not stopped by its deadline (GAP-0664)")
	}
}

// GAP-0946: the path the original stall dumps show (Tx.Exec ALTER TABLE ->
// sqlite3InitOne, the schema re-parse every ADD COLUMN runs) stops at the
// migration's deadline. The schema is large, so every ALTER re-parses a
// few hundred tables, indexes and triggers; the migration adds columns
// until something stops it.
func TestApplyMigrationStopsAnAlterSchemaReparseAtTheDeadline(t *testing.T) {
	store, err := NewStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	const tables = 150
	for i := 0; i < tables; i++ {
		for _, q := range []string{
			fmt.Sprintf(`CREATE TABLE t%d (id INTEGER PRIMARY KEY, a TEXT, b TEXT, c INTEGER)`, i),
			fmt.Sprintf(`CREATE INDEX t%d_a ON t%d (a)`, i, i),
			fmt.Sprintf(`CREATE INDEX t%d_bc ON t%d (b, c)`, i, i),
			fmt.Sprintf(`CREATE TRIGGER t%d_ins AFTER INSERT ON t%d BEGIN UPDATE t%d SET c = c + 1 WHERE id = NEW.id; END`, i, i, i),
		} {
			if _, err := store.db.Exec(q); err != nil {
				t.Fatal(err)
			}
		}
	}
	shortMigrationLimit(store, 300*time.Millisecond)
	var alters atomic.Int64
	adds := migration{description: "test: ALTER TABLE ADD COLUMN on a large schema, without end", apply: func(ex dbExecer) error {
		for i := 0; ; i++ {
			if _, err := ex.Exec(fmt.Sprintf(`ALTER TABLE t%d ADD COLUMN x%d INTEGER`, i%tables, i)); err != nil {
				return err
			}
			alters.Add(1)
		}
	}}

	done := make(chan error, 1)
	go func() { done <- store.applyMigration(1, adds) }()
	select {
	case err := <-done:
		if err == nil || (!errors.Is(err, context.DeadlineExceeded) && !isInterrupted(err)) {
			t.Fatalf("the ALTER migration did not end at its deadline: %v", err)
		}
		if alters.Load() == 0 {
			t.Fatal("no ALTER ran before the deadline; the test did not reach the schema re-parse")
		}
		t.Logf("stopped after %d ALTERs: %v", alters.Load(), err)
	case <-time.After(20 * time.Second):
		t.Fatalf("an ALTER migration (%d ALTERs so far) was not stopped by its deadline (GAP-0946)", alters.Load())
	}
}

func isInterrupted(err error) bool {
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "interrupted") || strings.Contains(text, "deadline")
}
