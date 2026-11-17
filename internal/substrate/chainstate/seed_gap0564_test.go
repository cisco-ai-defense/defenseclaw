// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package chainstate

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// readinessGeneration is the readiness write count of an actor's store: one
// per audit store open of it. A store migrated in place has been opened
// once; a copy of the seed carries the seed's open too.
func readinessGeneration(t *testing.T, path string) int64 {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int64
	if err := db.QueryRow(`SELECT verification_generation FROM observability_store_readiness WHERE id = 1`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestSubstrateGAP0564NewActorStoreIsASeedCopy: substrate-1 GAP-0564. A new
// actor's chain store is a copy of the store the leader migrated once, not a
// store that runs every audit migration again (50 of those at once kept J43's
// first chain calls waiting up to 15 s). The copy is a working store, a
// store that exists is never replaced, and the seed is gone when the leader
// closes.
func TestSubstrateGAP0564NewActorStoreIsASeedCopy(t *testing.T) {
	dir := t.TempDir()
	h := newHarness(t, dir, Options{})
	h.hook(actorA, "s1", projection(t, guardrail.ToolChainSecretReadThenEgress, 1))
	h.hook(actorB, "s1", projection(t, reverseShell, 1))
	seeds, err := filepath.Glob(filepath.Join(dir, "chains", ".seed", "seed-*", "store.db"))
	if err != nil || len(seeds) != 1 {
		t.Fatalf("seed stores %v err=%v, want one", seeds, err)
	}
	h.advance(time.Second)
	if v, err := h.egress(actorA); err != nil || !v.Deny {
		t.Fatalf("a seeded store keeps the chain: %+v %v", v, err)
	}
	if v, err := h.egress(actorB); err != nil || v.Deny {
		t.Fatalf("the other seeded store: %+v %v", v, err)
	}
	h.srv.Close()
	if err := h.svc.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Dir(seeds[0])); !os.IsNotExist(err) {
		t.Fatalf("the seed folder outlived the leader: %v", err)
	}
	for _, a := range []Actor{actorA, actorB} {
		if n := readinessGeneration(t, filepath.Join(dir, "chains", a.Atespace, a.UID+".db")); n != 2 {
			t.Fatalf("%s: store opened %d times, want 2 (the seed's open and its own): the store was migrated in place", a.UID, n)
		}
	}
	// A new leader on the same volume opens the stores as they are.
	n := newHarness(t, dir, Options{})
	n.now = h.clock()
	if v, err := n.egress(actorA); err != nil || !v.Deny {
		t.Fatalf("a new leader: %+v %v", v, err)
	}
}

// TestSubstrateGAP0564SeedFailureMigratesInPlace: when the seed can't be
// made, a new actor's store is migrated in place as before.
func TestSubstrateGAP0564SeedFailureMigratesInPlace(t *testing.T) {
	dir := t.TempDir()
	h := newHarness(t, dir, Options{})
	// A file where the seed folder goes: the seed can't be made.
	if err := os.WriteFile(filepath.Join(dir, "chains", ".seed"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.hook(actorA, "s1", projection(t, guardrail.ToolChainSecretReadThenEgress, 1))
	h.advance(time.Second)
	if v, err := h.egress(actorA); err != nil || !v.Deny {
		t.Fatalf("an actor whose store was migrated in place: %+v %v", v, err)
	}
}
