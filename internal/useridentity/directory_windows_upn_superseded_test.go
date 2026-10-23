// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package useridentity

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// W19 review (loop round 2): with more than 4096 cached identities an
// eviction lets a second translation of the same SID start while the first
// still runs. Whichever finishes last is stored, as before (the answers
// lookup gives for profile matching are unchanged, GAP-0129), but the answer
// of a translation a newer one overtook is never reported confirmed, so an
// agent identity row does not list an old UPN as current after a rename.
func TestADUPNCacheNeverConfirmsAnOvertakenTranslation(t *testing.T) {
	const sid, sam = "S-1-5-21-1-2-3-1105", `CORP\alice`
	key := strings.ToUpper(sid) + "\x00" + strings.ToLower(sam)
	const oldUPN, newUPN = "old@corp.example.com", "new@corp.example.com"

	type translation struct {
		reply chan string
		done  chan struct{}
	}
	setup := func(t *testing.T) (cache *adUPNCache, start func() translation, evict func(), now *time.Time) {
		t.Helper()
		started := make(chan chan string, 8)
		cache = newADUPNCache(func(name string) string {
			if name != sam {
				return ""
			}
			reply := make(chan string)
			started <- reply
			return <-reply
		})
		clock := time.Unix(1_800_000_000, 0)
		cache.now = func() time.Time { return clock }
		start = func() translation {
			t.Helper()
			cache.lookup(sid, sam, 0)
			var reply chan string
			select {
			case reply = <-started:
			case <-time.After(10 * time.Second):
				t.Fatal("lookup started no translation")
			}
			cache.mu.Lock()
			done := cache.entries[key].done
			cache.mu.Unlock()
			if done == nil {
				t.Fatal("no translation running")
			}
			return translation{reply: reply, done: done}
		}
		evictions := 0
		evict = func() {
			t.Helper()
			cache.mu.Lock()
			for i := range 4097 {
				cache.entries[fmt.Sprintf("other-%d", i)] = adUPNEntry{expires: clock.Add(time.Hour)}
			}
			cache.mu.Unlock()
			// A SID not cached yet, so its lookup starts a translation and
			// clears the cache; a second eviction must not reuse the first's.
			evictions++
			cache.lookup(fmt.Sprintf("S-1-5-21-1-2-3-%d", 9000+evictions), `CORP\bob`, time.Second)
			cache.mu.Lock()
			left := len(cache.entries)
			cache.mu.Unlock()
			if left > 2 {
				t.Fatalf("eviction left %d entries", left)
			}
		}
		return cache, start, evict, &clock
	}
	finish := func(tr translation, answer string) {
		tr.reply <- answer
		<-tr.done
	}
	check := func(t *testing.T, cache *adUPNCache, step, want string, wantUnconfirmed bool) {
		t.Helper()
		got := cache.lookup(sid, sam, 0)
		if unconfirmed := cache.unconfirmed(sid, sam, got); got != want || unconfirmed != wantUnconfirmed {
			t.Fatalf("%s: lookup = %q, unconfirmed %t; want %q, unconfirmed %t", step, got, unconfirmed, want, wantUnconfirmed)
		}
	}

	t.Run("old translation finishes after the newer one", func(t *testing.T) {
		cache, start, evict, now := setup(t)
		first := start()
		evict()
		second := start()
		finish(second, newUPN)
		check(t, cache, "newer translation done", newUPN, false)
		finish(first, oldUPN)
		check(t, cache, "overtaken translation done", oldUPN, true)
		if !cache.unconfirmed(sid, sam, newUPN) {
			t.Fatal("an answer the cache no longer holds is reported confirmed")
		}
		*now = now.Add(adUPNTTL)
		refresh := start()
		check(t, cache, "refresh running after an overtaken answer", oldUPN, true)
		finish(refresh, newUPN)
		check(t, cache, "refresh verified", newUPN, false)
	})
	t.Run("old translation finishes while the newer one runs", func(t *testing.T) {
		cache, start, evict, _ := setup(t)
		first := start()
		evict()
		second := start()
		finish(first, oldUPN)
		check(t, cache, "overtaken translation done", oldUPN, true)
		finish(second, newUPN)
		check(t, cache, "newer translation done", newUPN, false)
	})
	t.Run("overtaken translation that fails", func(t *testing.T) {
		cache, start, evict, now := setup(t)
		verify := start()
		finish(verify, oldUPN)
		*now = now.Add(adUPNTTL)
		first := start()
		evict()
		second := start()
		finish(second, newUPN)
		finish(first, "")
		// The failed translation started from the old answer it kept.
		check(t, cache, "overtaken failed translation done", oldUPN, true)
	})
	t.Run("a newer translation dropped by a second eviction", func(t *testing.T) {
		cache, start, evict, _ := setup(t)
		first := start()
		evict()
		second := start()
		evict()
		finish(first, oldUPN)
		check(t, cache, "translation that may be overtaken done", oldUPN, true)
		finish(second, newUPN)
		check(t, cache, "newest translation done", newUPN, false)
	})
	// W19 review (loop round 3): with three overlapping translations an older
	// completion repopulates the evicted entry, and a middle one that finishes
	// next must still not be confirmed while the newest runs. Every completion
	// order, with and without an eviction after the newest starts: only the
	// newest translation's answer is ever confirmed, and lookup always gives
	// the answer stored last (GAP-0129).
	for _, order := range [][3]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}} {
		for _, evictAfterNewest := range []bool{false, true} {
			name := fmt.Sprintf("three translations finish in order %d%d%d, eviction after the newest %t",
				order[0], order[1], order[2], evictAfterNewest)
			t.Run(name, func(t *testing.T) {
				cache, start, evict, _ := setup(t)
				answers := [3]string{"first@corp.example.com", "second@corp.example.com", "third@corp.example.com"}
				var running [3]translation
				for i := range running {
					if i > 0 {
						evict()
					}
					running[i] = start()
				}
				if evictAfterNewest {
					evict()
				}
				for _, i := range order {
					finish(running[i], answers[i])
					check(t, cache, fmt.Sprintf("translation %d done", i), answers[i], i != 2)
				}
				if cache.unconfirmed(sid, sam, answers[2]) != (order[2] != 2) {
					t.Fatalf("newest answer confirmed %t after all finished in order %v",
						!cache.unconfirmed(sid, sam, answers[2]), order)
				}
				cache.mu.Lock()
				left := len(cache.inflight)
				cache.mu.Unlock()
				if left != 0 {
					t.Fatalf("inflight keeps %d identities after every translation finished", left)
				}
			})
		}
	}
	t.Run("one eviction and no newer translation", func(t *testing.T) {
		cache, start, evict, _ := setup(t)
		first := start()
		evict()
		finish(first, newUPN)
		check(t, cache, "the only translation done", newUPN, false)
	})
}
