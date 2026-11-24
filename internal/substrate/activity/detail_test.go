// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package activity

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// B3.6: the per-kind times reach the gateway only when it asks (Detail); the
// controller's snapshot does not grow; a replica cannot grow the store by
// inventing kinds.
func TestSnapshotDetailCarriesKinds(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := &Store{Now: func() time.Time { return now }}
	_, _ = s.Observe(context.Background(), Batch{Entries: []Entry{
		{Atespace: "a", UID: "u1", Last: map[string]time.Time{KindHook: now.Add(-43 * time.Second), KindModel: now.Add(-41 * time.Second)}},
	}})
	plain, _ := s.Snapshot(context.Background(), SnapshotRequest{})
	if plain.Kinds != nil {
		t.Fatalf("the controller's snapshot carries kinds: %v", plain.Kinds)
	}
	det, _ := s.Snapshot(context.Background(), SnapshotRequest{Detail: true})
	if !det.Kinds[KindModel]["u1"].Equal(now.Add(-41*time.Second)) || !det.Kinds[KindHook]["u1"].Equal(now.Add(-43*time.Second)) {
		t.Fatalf("kinds = %v", det.Kinds)
	}
	// the answer is a copy: changing it does not change the store
	det.Kinds[KindModel]["u1"] = time.Time{}
	again, _ := s.Snapshot(context.Background(), SnapshotRequest{Detail: true})
	if again.Kinds[KindModel]["u1"].IsZero() {
		t.Fatal("the snapshot shares the store's map")
	}
}

func TestSnapshotKindsAreBounded(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := &Store{Now: func() time.Time { return now }}
	last := map[string]time.Time{}
	for i := 0; i < 40; i++ {
		last[fmt.Sprintf("kind%d", i)] = now
	}
	_, _ = s.Observe(context.Background(), Batch{Entries: []Entry{{Atespace: "a", UID: "u1", Last: last}}})
	det, _ := s.Snapshot(context.Background(), SnapshotRequest{Detail: true})
	if len(det.Kinds) > maxKinds {
		t.Fatalf("kinds = %d, want <= %d", len(det.Kinds), maxKinds)
	}
}
