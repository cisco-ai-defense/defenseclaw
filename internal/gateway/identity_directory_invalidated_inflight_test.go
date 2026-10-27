// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Review of r104 Q-identity (continuation 3, loop round 1): an
// invalidation (a profile assignment change, a guardian record that says
// the directory changed the account) that lands while a lookup is in flight
// was answered by that lookup. Its facts were stamped when it finished, so
// they counted as fetched after the invalidation, although the lookup had
// read the directory before the change. A blocking read now waits for a
// lookup started after the invalidation. Every OS reads through this cache.
func TestInvalidationDuringALookupIsNotAnsweredByIt(t *testing.T) {
	for _, how := range []string{"invalidate", "refreshSoon"} {
		t.Run(how, func(t *testing.T) {
			cache, clock, lookups, release := inflightInvalidationFixture(t)
			if got, ok := cache.get("k", true); !ok || got != "answer 1" {
				t.Fatalf("cold read = %q, %t", got, ok)
			}
			startInflightLookup(t, cache, clock, lookups)
			invalidateDuringLookup(cache, clock, how)
			release()
			waitIdentityCacheIdle(t, cache, "k")
			if got, ok := cache.get("k", true); !ok || got != "answer 3" {
				t.Fatalf("blocking read after an invalidation that landed during lookup 2 = %q, %t (%d lookups); "+
					"want the lookup started after it (answer 3)", got, ok, lookups.Load())
			}
			if got, ok := cache.get("k", true); !ok || got != "answer 3" || lookups.Load() != 3 {
				t.Fatalf("next read = %q, %t after %d lookups; want answer 3 from the cache", got, ok, lookups.Load())
			}
		})
	}
}

// inflightInvalidationFixture is a string cache on a test clock whose second
// lookup blocks until release is called.
func inflightInvalidationFixture(t *testing.T) (*identityCache[string], *atomic.Int64, *atomic.Int32, func()) {
	t.Helper()
	lookups := new(atomic.Int32)
	gate := make(chan struct{})
	release := sync.OnceFunc(func() { close(gate) })
	t.Cleanup(release)
	cache := newIdentityCache(func(string) (string, error) {
		n := lookups.Add(1)
		if n == 2 {
			<-gate
		}
		return "answer " + strconv.Itoa(int(n)), nil
	})
	clock := new(atomic.Int64)
	clock.Store(time.Unix(1_000_000, 0).UnixNano())
	cache.now = func() time.Time { return time.Unix(0, clock.Load()) }
	return cache, clock, lookups, release
}

// startInflightLookup expires answer 1 and starts lookup 2 in the
// background, as a read that does not wait does.
func startInflightLookup(t *testing.T, cache *identityCache[string], clock *atomic.Int64, lookups *atomic.Int32) {
	t.Helper()
	clock.Add(int64(identityDirectoryTTL + time.Second))
	if got, ok := cache.get("k", false); !ok || got != "answer 1" {
		t.Fatalf("expired read = %q, %t; want answer 1 while the refresh runs", got, ok)
	}
	deadline := time.Now().Add(2 * time.Second)
	for lookups.Load() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("lookup 2 did not start")
		}
		time.Sleep(time.Millisecond)
	}
}

func invalidateDuringLookup(cache *identityCache[string], clock *atomic.Int64, how string) {
	clock.Add(int64(time.Millisecond))
	if how == "invalidate" {
		cache.invalidate()
	} else {
		cache.refreshSoon("k")
	}
}

func waitIdentityCacheIdle(t *testing.T, cache *identityCache[string], key string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		cache.mu.Lock()
		entry := cache.entries[key]
		idle := entry != nil && entry.inflight == nil
		cache.mu.Unlock()
		if idle {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("lookup did not finish")
		}
		time.Sleep(time.Millisecond)
	}
}
