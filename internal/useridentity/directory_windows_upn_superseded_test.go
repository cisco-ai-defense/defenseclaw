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
			reply := <-started
			cache.mu.Lock()
			done := cache.entries[key].done
			cache.mu.Unlock()
			if done == nil {
				t.Fatal("no translation running")
			}
			return translation{reply: reply, done: done}
		}
		evict = func() {
			t.Helper()
			cache.mu.Lock()
			for i := range 4097 {
				cache.entries[fmt.Sprintf("other-%d", i)] = adUPNEntry{expires: clock.Add(time.Hour)}
			}
			cache.mu.Unlock()
			cache.lookup("S-1-5-21-1-2-3-9999", `CORP\bob`, time.Second) // clears the cache
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
	t.Run("one eviction and no newer translation", func(t *testing.T) {
		cache, start, evict, _ := setup(t)
		first := start()
		evict()
		finish(first, newUPN)
		check(t, cache, "the only translation done", newUPN, false)
	})
}
