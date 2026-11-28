// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStateTreePastWatchLimitIsWalkedOncePerInterval(t *testing.T) {
	resetActiveStateIndex(t)
	home, _ := activeStateIndexFixture(t, 0)
	root := mustResolve(t, filepath.Join(home, ".defenseclaw"))
	cache := filepath.Join(root, "cache")
	for i := 0; i < activeStateViewWatches+16; i++ {
		dir := filepath.Join(cache, fmt.Sprintf("dir-%03d", i))
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "item"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Keep timing out of the verdict: the pause only lets fixture metadata
	// settle so the index can use its change-time validation.
	time.Sleep(200 * time.Millisecond)
	probe := &activeStateWalk{limit: activeStateIndexEntries, record: true, visit: func(string, os.FileInfo) bool { return false }}
	probe.run(root)
	if len(probe.watches) <= activeStateViewWatches {
		t.Fatalf("fixture has %d watches, want over %d", len(probe.watches), activeStateViewWatches)
	}
	before := activeStateIndexWalks.Load()
	start := time.Now()
	for range 3 {
		if _, unanswered := activeStateIdentities(root); unanswered {
			t.Fatal("local state walk unanswered")
		}
	}
	t.Logf("three calls: %s", time.Since(start))
	if walks := activeStateIndexWalks.Load() - before; walks != 1 {
		t.Fatalf("unchanged over-watch-limit state walked %d times, want 1", walks)
	}
	// The full validation list still catches a change in the large tree.
	if err := os.WriteFile(filepath.Join(cache, "dir-000", "new"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, unanswered := activeStateIdentities(root); unanswered {
		t.Fatal("changed local state walk unanswered")
	}
	if walks := activeStateIndexWalks.Load() - before; walks != 2 {
		t.Fatalf("changed state walked %d times, want 2", walks)
	}
}
