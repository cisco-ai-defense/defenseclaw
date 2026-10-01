// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"testing"
	"time"
)

func TestCollectSQLiteHealthPinsReadyStoreAndReturnsBoundedValues(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	snapshot, err := store.CollectSQLiteHealth(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.DBSizeBytes <= 0 || snapshot.WALSizeBytes < 0 || snapshot.PageCount <= 0 ||
		snapshot.FreelistCount < 0 || snapshot.CheckpointMs < 0 {
		t.Fatalf("invalid SQLite health snapshot: %+v", snapshot)
	}
}

func TestCollectSQLiteHealthRejectsInvalidLifecycle(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	if _, err := store.CollectSQLiteHealth(nil); err == nil {
		t.Fatal("nil context accepted")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CollectSQLiteHealth(context.Background()); err == nil {
		t.Fatal("closed store accepted")
	}
}

// A checkpoint copies WAL frames and syncs the database, which takes seconds
// on slow storage. It must not wait for, or hold, the single writer connection
// that mandatory appends use.
func TestPassiveCheckpointDoesNotNeedWriterConnection(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	writer, err := store.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Rollback()
	if _, err := writer.Exec(`CREATE TABLE checkpoint_writer_probe (id INTEGER)`); err != nil {
		t.Fatal(err)
	}
	release, err := store.acquireReady()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	// With the writer connection held, this returns only if the checkpoint
	// runs on its own connection; the deadline turns a regression into a
	// failure instead of a hang.
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if _, err := store.passiveCheckpoint(ctx); err != nil {
		t.Fatal(err)
	}
}
