// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"path/filepath"
	"testing"
)

// GAP-0404: a store one of many in a process keeps open (the Substrate
// leader's per-actor chain stores) opens with a small page cache on every
// connection and no read pool; the gateway's own store keeps its 20 MB
// cache and its read pool.
func TestGAP0404SmallFootprintStoreBoundsItsPageCache(t *testing.T) {
	ctx := context.Background()
	cacheOf := func(t *testing.T, s *Store) int64 {
		t.Helper()
		var got int64
		if err := s.db.QueryRowContext(ctx, "PRAGMA cache_size").Scan(&got); err != nil {
			t.Fatal(err)
		}
		return got
	}
	small, err := NewStore(filepath.Join(t.TempDir(), "chain.db"), WithSmallFootprint())
	if err != nil {
		t.Fatal(err)
	}
	defer small.Close()
	if err := small.Init(); err != nil {
		t.Fatal(err)
	}
	if got := cacheOf(t, small); got != -SmallFootprintPageCacheKiB {
		t.Fatalf("small-footprint writer cache_size %d, want %d", got, -SmallFootprintPageCacheKiB)
	}
	if small.readDB != nil || small.queryPool() != small.db {
		t.Fatal("a small-footprint store opened a read pool")
	}
	cp, err := small.checkpointConn()
	if err != nil {
		t.Fatal(err)
	}
	var got int64
	if err := cp.QueryRowContext(ctx, "PRAGMA cache_size").Scan(&got); err != nil || got != -SmallFootprintPageCacheKiB {
		t.Fatalf("small-footprint checkpoint connection cache_size %d (%v), want %d", got, err, -SmallFootprintPageCacheKiB)
	}

	full, err := NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer full.Close()
	if err := full.Init(); err != nil {
		t.Fatal(err)
	}
	if got := cacheOf(t, full); got != -20000 {
		t.Fatalf("the gateway store cache_size changed: %d", got)
	}
	if full.readDB == nil {
		t.Fatal("the gateway store lost its read pool")
	}
}
