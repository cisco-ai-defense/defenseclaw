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

// closeBifrostTenantsAfter shuts down, when t ends, the tenant clients t added
// to the process-wide cache. Each holds schemas.DefaultConcurrency (1000)
// request workers until it is evicted, and a test's upstream (a new
// httptest URL, so a new tenant) is gone once the test ends: in a whole
// internal/gateway run the 13 tests that call this left 57 clients, 57,000 of
// the 57,116 goroutines alive when later tests started, and the heap they
// measured (rel-1-0-10:GAP-1659, GAP-1558). Only for tests that do not run in
// parallel: no other test adds a client while they run.
func closeBifrostTenantsAfter(t *testing.T) {
	t.Helper()
	bifrostTenantsMu.Lock()
	before := make(map[tenantKey]bool, len(bifrostTenants))
	for k := range bifrostTenants {
		before[k] = true
	}
	bifrostTenantsMu.Unlock()
	t.Cleanup(func() {
		var added []*bifrost.Bifrost
		bifrostTenantsMu.Lock()
		for k, e := range bifrostTenants {
			if !before[k] {
				delete(bifrostTenants, k)
				if e != nil && e.client != nil {
					added = append(added, e.client)
				}
			}
		}
		bifrostTenantsMu.Unlock()
		for _, c := range added {
			c.Shutdown()
		}
	})
}

// GAP-1760: a tenant client nobody asks for any more (a rotated key, a changed
// base_url) was shut down only when 256 newer tenants pushed it out, and held
// 1000 idle request workers until then. A new tenant now releases the clients
// that have been idle for bifrostTenantIdleTTL; a fresh one stays.
func TestNewBifrostTenantReleasesIdleClients(t *testing.T) {
	closeBifrostTenantsAfter(t)
	shutdowns := make(chan *bifrost.Bifrost, 4)
	originalShutdown := shutdownEvictedBifrostClient
	shutdownEvictedBifrostClient = func(c *bifrost.Bifrost) { shutdowns <- c }
	t.Cleanup(func() { shutdownEvictedBifrostClient = originalShutdown })

	idle := &bifrost.Bifrost{}
	fresh := &bifrost.Bifrost{}
	idleKey := tenantKey{provider: "openai", keyID: "idle-old-key"}
	freshKey := tenantKey{provider: "openai", keyID: "fresh-key"}
	bifrostTenantsMu.Lock()
	bifrostTenants[idleKey] = &bifrostTenantEntry{client: idle, lastUsed: time.Now().Add(-2 * time.Hour)}
	bifrostTenants[freshKey] = &bifrostTenantEntry{client: fresh, lastUsed: time.Now().Add(-time.Minute)}
	bifrostTenantsMu.Unlock()
	t.Cleanup(func() {
		bifrostTenantsMu.Lock()
		delete(bifrostTenants, idleKey)
		delete(bifrostTenants, freshKey)
		bifrostTenantsMu.Unlock()
	})

	// A request for a tenant that is not cached (a rotated key).
	if _, err := getBifrostClient(schemas.OpenAI, "sk-rotated-key", "http://127.0.0.1:1", "gpt-x", tlsOverrides{}, nil, nil, nil, nil); err != nil {
		t.Fatalf("getBifrostClient: %v", err)
	}

	select {
	case got := <-shutdowns:
		if got != idle {
			t.Fatalf("Shutdown called with %p, want the idle client %p", got, idle)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the idle tenant client was not shut down when a new tenant was added")
	}
	select {
	case got := <-shutdowns:
		t.Fatalf("Shutdown called again with %p; the fresh client must stay", got)
	case <-time.After(200 * time.Millisecond):
	}
	bifrostTenantsMu.RLock()
	_, idleStill := bifrostTenants[idleKey]
	_, freshStill := bifrostTenants[freshKey]
	bifrostTenantsMu.RUnlock()
	if idleStill || !freshStill {
		t.Fatalf("cache after the sweep: idle kept=%v (want false), fresh kept=%v (want true)", idleStill, freshStill)
	}
}
