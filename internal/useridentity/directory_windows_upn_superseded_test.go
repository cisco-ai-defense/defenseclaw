// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package useridentity

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// W19 review (loop rounds 2 and 3, continuation 5): with more than 4096
// cached identities an eviction lets newer translations of the same SID
// start while older ones still run, and they finish in any order. The cache
// holds the answer of the newest translation that answered: a newer answer
// replaces an older one, an older or evicted translation never puts its
// answer back, and only the newest translation started can confirm its
// answer, so an agent identity row never lists an overtaken UPN as current.
// A failure of the newest translation keeps the last good answer for
// profile matching (GAP-0129), unconfirmed.
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
	// check reads the entry without starting a translation; an evicted
	// entry gives no answer. A cached one is also what lookup gives.
	check := func(t *testing.T, cache *adUPNCache, step, want string, wantConfirmed bool) {
		t.Helper()
		cache.mu.Lock()
		entry, present := cache.entries[key]
		cache.mu.Unlock()
		got := entry.upn
		if present {
			if looked := cache.lookup(sid, sam, 0); looked != got {
				t.Fatalf("%s: lookup = %q, entry %q", step, looked, got)
			}
		}
		confirmed := got != "" && !cache.unconfirmed(sid, sam, got)
		if got != want || confirmed != wantConfirmed {
			t.Fatalf("%s: answer %q, confirmed %t; want %q, confirmed %t", step, got, confirmed, want, wantConfirmed)
		}
	}

	// Every completion order of three overlapping translations (an eviction
	// before each newer one starts), with and without another eviction
	// after the newest starts, with every translation answering or one of
	// them failing. After each completion the answer is that of the newest
	// translation that answered so far, and it is confirmed only when it is
	// the newest translation's own.
	for _, order := range [][3]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}} {
		for _, evictAfterNewest := range []bool{false, true} {
			for _, failed := range []int{-1, 0, 1, 2} {
				name := fmt.Sprintf("order %d%d%d, eviction after the newest %t, failed %d",
					order[0], order[1], order[2], evictAfterNewest, failed)
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
					newestAnswered := -1
					for _, i := range order {
						answer := answers[i]
						if i == failed {
							answer = ""
						} else {
							newestAnswered = max(newestAnswered, i)
						}
						finish(running[i], answer)
						want := ""
						if newestAnswered >= 0 {
							want = answers[newestAnswered]
						}
						check(t, cache, fmt.Sprintf("translation %d done", i), want, newestAnswered == 2)
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
	}
	t.Run("a refresh after an overtaken answer", func(t *testing.T) {
		cache, start, evict, now := setup(t)
		first := start()
		evict()
		second := start()
		finish(second, newUPN)
		finish(first, oldUPN)
		check(t, cache, "overtaken translation done", newUPN, true)
		*now = now.Add(adUPNTTL)
		refresh := start()
		check(t, cache, "refresh running", newUPN, true)
		finish(refresh, newUPN)
		check(t, cache, "refresh verified", newUPN, true)
	})
	t.Run("an overtaken translation that started from a kept answer fails", func(t *testing.T) {
		cache, start, evict, now := setup(t)
		verify := start()
		finish(verify, oldUPN)
		*now = now.Add(adUPNTTL)
		first := start()
		evict()
		second := start()
		finish(second, newUPN)
		finish(first, "")
		check(t, cache, "overtaken failed translation done", newUPN, true)
	})
	t.Run("the newest translation fails after an eviction", func(t *testing.T) {
		cache, start, evict, now := setup(t)
		verify := start()
		finish(verify, oldUPN)
		*now = now.Add(adUPNTTL)
		first := start()
		evict()
		second := start()
		finish(first, newUPN)
		finish(second, "")
		// The last good answer is the overtaken translation's, kept and
		// not confirmed, and its retry comes after the failure lifetime.
		check(t, cache, "newest translation failed", newUPN, false)
		*now = now.Add(adUPNFailureTTL)
		retry := start()
		finish(retry, newUPN)
		check(t, cache, "retry verified", newUPN, true)
	})
	t.Run("one eviction and no newer translation", func(t *testing.T) {
		cache, start, evict, _ := setup(t)
		first := start()
		evict()
		finish(first, newUPN)
		check(t, cache, "the only translation done", newUPN, true)
	})
}
