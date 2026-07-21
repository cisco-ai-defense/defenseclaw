// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"testing"
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
