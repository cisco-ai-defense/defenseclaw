// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"testing"
	"time"

	bifrost "github.com/maximhq/bifrost/core"
	"github.com/maximhq/bifrost/core/schemas"
)

// TestEvictOldestBifrostTenantLocked_TieBreakDeterministic pins that
// when two tenant entries share the same lastUsed (which can happen
// under bursty traffic and definitely happens with low-resolution
// test wallclocks), eviction picks the lexicographically smallest
// tenantKeyString rather than relying on Go's randomized map
// iteration order. Without this guard the bursty-traffic eviction
// pattern is observably flaky.
//
// Operates on a local snapshot of the package-level map and restores
// the original map at the end so it does not poison sibling tests.
func TestEvictOldestBifrostTenantLocked_TieBreakDeterministic(t *testing.T) {
	bifrostTenantsMu.Lock()
	original := bifrostTenants
	bifrostTenants = make(map[tenantKey]*bifrostTenantEntry)
	bifrostTenantsMu.Unlock()
	t.Cleanup(func() {
		bifrostTenantsMu.Lock()
		bifrostTenants = original
		bifrostTenantsMu.Unlock()
	})

	fixed := time.Date(2026, 5, 9, 22, 0, 0, 0, time.UTC)
	bifrostTenantsMu.Lock()
	for i := 0; i < 5; i++ {
		k := tenantKey{
			provider: schemas.ModelProvider("openai"),
			baseURL:  "",
			keyID:    fmt.Sprintf("k-%05d", i),
		}
		// client=nil: the tie-break test never uses the cached
		// client, and eviction shuts down only real clients.
		bifrostTenants[k] = &bifrostTenantEntry{client: nil, lastUsed: fixed}
	}
	bifrostTenantsMu.Unlock()

	// Each eviction must drop the lexicographically smallest
	// keyString. Iterate to make the determinism contract obvious.
	for i := 0; i < 3; i++ {
		expectedVictim := fmt.Sprintf("k-%05d", i)
		bifrostTenantsMu.Lock()
		evictOldestBifrostTenantLocked()
		bifrostTenantsMu.Unlock()
		bifrostTenantsMu.RLock()
		stillThere := false
		for k := range bifrostTenants {
			if k.keyID == expectedVictim {
				stillThere = true
				break
			}
		}
		bifrostTenantsMu.RUnlock()
		if stillThere {
			t.Fatalf("iteration %d: expected keyID %q to be evicted (smallest in tie), still present",
				i, expectedVictim)
		}
	}
}

// TestEvictOldestBifrostTenantLocked_OldestFirst pins the primary
// LRU contract: when entries have distinct lastUsed timestamps,
// eviction picks the entry with the smallest lastUsed regardless of
// map ordering.
func TestEvictOldestBifrostTenantLocked_OldestFirst(t *testing.T) {
	bifrostTenantsMu.Lock()
	original := bifrostTenants
	bifrostTenants = make(map[tenantKey]*bifrostTenantEntry)
	bifrostTenantsMu.Unlock()
	t.Cleanup(func() {
		bifrostTenantsMu.Lock()
		bifrostTenants = original
		bifrostTenantsMu.Unlock()
	})

	base := time.Date(2026, 5, 9, 22, 0, 0, 0, time.UTC)
	expectedOldest := tenantKey{
		provider: schemas.ModelProvider("openai"),
		baseURL:  "",
		keyID:    "z-newer-key-but-oldest-time",
	}
	bifrostTenantsMu.Lock()
	bifrostTenants[expectedOldest] = &bifrostTenantEntry{client: nil, lastUsed: base}
	bifrostTenants[tenantKey{provider: "openai", keyID: "a-mid"}] = &bifrostTenantEntry{
		client: nil, lastUsed: base.Add(time.Second),
	}
	bifrostTenants[tenantKey{provider: "openai", keyID: "b-newest"}] = &bifrostTenantEntry{
		client: nil, lastUsed: base.Add(2 * time.Second),
	}
	bifrostTenantsMu.Unlock()

	bifrostTenantsMu.Lock()
	evictOldestBifrostTenantLocked()
	bifrostTenantsMu.Unlock()

	bifrostTenantsMu.RLock()
	_, oldestStillThere := bifrostTenants[expectedOldest]
	bifrostTenantsMu.RUnlock()
	if oldestStillThere {
		t.Fatalf("expected oldest entry to be evicted; lexicographic key was largest but lastUsed was smallest")
	}
}

// rel-1-0-6:GAP-0550: evicting an entry that holds no client must not call
// Shutdown. The call on nil faulted (a hardware access violation recovered on
// a fresh goroutine), which on Windows AMX hosts corrupts the heap below that
// goroutine's stack (golang/go#81238).
func TestEvictOldestBifrostTenantLockedShutsDownOnlyRealClients(t *testing.T) {
	bifrostTenantsMu.Lock()
	original := bifrostTenants
	bifrostTenants = make(map[tenantKey]*bifrostTenantEntry)
	bifrostTenantsMu.Unlock()
	shutdowns := make(chan *bifrost.Bifrost, 4)
	originalShutdown := shutdownEvictedBifrostClient
	shutdownEvictedBifrostClient = func(c *bifrost.Bifrost) { shutdowns <- c }
	t.Cleanup(func() {
		bifrostTenantsMu.Lock()
		bifrostTenants = original
		bifrostTenantsMu.Unlock()
		shutdownEvictedBifrostClient = originalShutdown
	})

	real := &bifrost.Bifrost{}
	base := time.Date(2026, 5, 9, 22, 0, 0, 0, time.UTC)
	bifrostTenantsMu.Lock()
	bifrostTenants[tenantKey{provider: "openai", keyID: "no-client"}] = &bifrostTenantEntry{client: nil, lastUsed: base}
	bifrostTenants[tenantKey{provider: "openai", keyID: "client"}] = &bifrostTenantEntry{client: real, lastUsed: base.Add(time.Second)}
	evictOldestBifrostTenantLocked()
	evictOldestBifrostTenantLocked()
	bifrostTenantsMu.Unlock()

	select {
	case got := <-shutdowns:
		if got != real {
			t.Fatalf("Shutdown called with %p, want the evicted client %p", got, real)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the evicted client was not shut down")
	}
	select {
	case got := <-shutdowns:
		t.Fatalf("Shutdown called again (with %p); an entry without a client has nothing to shut down", got)
	case <-time.After(200 * time.Millisecond):
	}
}

// Note: a direct unit test for the previous getBifrostClient TOCTOU
// race is intentionally omitted. The fix collapsed the
// double-checked-locking variant into a single Lock-only path (see
// the inline comment in getBifrostClient), so there is no longer a
// window between RLock and Lock during which an eviction can
// concurrently call client.Shutdown() on the cached client we are
// about to return. The two LRU eviction tests above plus
// TestGetBifrostClient_LRUEvictsOldestOnInsert exercise the
// observable contracts that matter; reproducing the deleted TOCTOU
// race would require a SDK mock infrastructure disproportionate to
// the value.
