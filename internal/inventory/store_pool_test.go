// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestInventoryStore_ConcurrentWritersSerialize fires a burst of
// PruneScansBefore calls in parallel to confirm the inventory store
// can absorb the same kind of write contention the audit store
// guards against. The interesting failure mode is `database is
// locked` returning to the caller; with MaxOpenConns(1) + retryBusy
// in place, every prune should succeed even when the DB has no
// matching rows to delete.
func TestInventoryStore_ConcurrentWritersSerialize(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "inventory.db")
	st, err := NewInventoryStore(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	const writers = 32
	ctx := context.Background()
	cutoff := time.Now().UTC()

	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := st.PruneScansBefore(ctx, cutoff); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("PruneScansBefore returned error: %v", err)
		}
	}
}

// TestInventoryStore_PragmasAppliedAcrossPool mirrors the audit
// store test: the pragma values we configure in the DSN must show
// up on every connection in the pool. Bug guarded against: PRAGMA
// busy_timeout set via db.Exec only mutates the connection that
// served it.
func TestInventoryStore_PragmasAppliedAcrossPool(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "inventory.db")
	st, err := NewInventoryStore(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	cases := []struct {
		pragma string
		want   int64
	}{
		{"busy_timeout", 5000},
		{"synchronous", 1}, // NORMAL
		{"foreign_keys", 1},
	}
	for _, tc := range cases {
		var got int64
		if err := st.db.QueryRow("PRAGMA " + tc.pragma).Scan(&got); err != nil {
			t.Fatalf("read pragma %s: %v", tc.pragma, err)
		}
		if got != tc.want {
			t.Fatalf("pragma %s: want %d, got %d", tc.pragma, tc.want, got)
		}
	}

	var jm string
	if err := st.db.QueryRow("PRAGMA journal_mode").Scan(&jm); err != nil {
		t.Fatalf("read journal_mode: %v", err)
	}
	if jm != "wal" {
		t.Fatalf("journal_mode: want wal, got %q", jm)
	}
}
