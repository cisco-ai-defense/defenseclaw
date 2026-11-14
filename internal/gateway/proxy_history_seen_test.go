// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// The inspect-once record (GAP-0244): bounded, fail-safe LRU per actor or
// session.

// A segment evicted from the LRU is inspected again when the client sends it
// back.
func TestGAP0244LRUEvictionReinspects(t *testing.T) {
	covAllowPrivate(t)
	for _, w := range f14Wires() {
		t.Run(w.name, func(t *testing.T) {
			rg := newF14Rig(t, w.provider, "action")
			rg.proxy.cfg.HistorySeenMax = 4
			c := f14Caller{session: "lru", owner: true}
			const old = "lru-old-turn-text"
			send := func(items ...f14Item) {
				t.Helper()
				if fwd, rec := rg.post(t, w, c, items, false); !fwd {
					t.Fatalf("a benign request was refused (status %d): %s", rec.Code, rec.Body)
				}
			}
			send(f14Item{"user", old})
			send(f14Item{"user", old}, f14Item{"assistant", "lru-answer-0"}, f14Item{"user", "lru-next-0"})
			if n := rg.insp.inspections(old); n != 1 {
				t.Fatalf("a recorded segment was inspected %d times, want 1", n)
			}
			// Four new segments push the old one out of a cap of 4.
			for i := 1; i <= 4; i++ {
				send(f14Item{"user", fmt.Sprintf("lru-fill-%d", i)})
			}
			send(f14Item{"user", old}, f14Item{"assistant", "lru-answer-0"}, f14Item{"user", "lru-next-1"})
			if n := rg.insp.inspections(old); n != 2 {
				t.Errorf("an evicted segment was inspected %d times in all, want 2 (new, then after eviction)", n)
			}
		})
	}
}

func TestGAP0244RecordUnit(t *testing.T) {
	allow := &ScanVerdict{Action: "allow"}
	t.Run("miss-is-fresh", func(t *testing.T) {
		var s historySeen
		if got := s.fresh("k", []string{"a", "b", "a"}); len(got) != 2 {
			t.Errorf("fresh on an empty record = %q, want a and b once", got)
		}
	})
	t.Run("unverified-records-nothing", func(t *testing.T) {
		var s historySeen
		s.record("", []string{"a"}, allow, 0)
		if got := s.fresh("", []string{"a"}); len(got) != 1 {
			t.Errorf("an unverified caller skipped a segment: %q", got)
		}
	})
	t.Run("failed-judge-records-nothing", func(t *testing.T) {
		var s historySeen
		s.record("k", []string{"a"}, &ScanVerdict{Action: "allow", JudgeFailed: true}, 0)
		if got := s.fresh("k", []string{"a"}); len(got) != 1 {
			t.Errorf("a segment whose judge failed was skipped: %q", got)
		}
	})
	t.Run("scopes-are-separate", func(t *testing.T) {
		var s historySeen
		s.record("k1", []string{"a"}, allow, 0)
		if got := s.fresh("k2", []string{"a"}); len(got) != 1 {
			t.Errorf("one scope's record skipped a segment of another: %q", got)
		}
		if got := s.fresh("k1", []string{"a"}); len(got) != 0 {
			t.Errorf("a recorded segment was fresh: %q", got)
		}
	})
	t.Run("keeps-verdict", func(t *testing.T) {
		var s historySeen
		s.record("k", []string{"a"}, &ScanVerdict{Action: "block"}, 0)
		s.record("k", []string{"a"}, allow, 0)
		e := s.scopes["k"].Value.(*historyScopeSet).byHash[historyHashOf("a")].Value.(*historyEntry)
		if e.verdict != historyBlocked {
			t.Errorf("recorded verdict = %d, want blocked kept", e.verdict)
		}
	})
	t.Run("default-cap", func(t *testing.T) {
		var s historySeen
		segs := make([]string, config.DefaultHistorySeenMax+10)
		for i := range segs {
			segs[i] = fmt.Sprintf("seg-%d", i)
		}
		s.record("k", segs, allow, 0)
		if n := s.scopes["k"].Value.(*historyScopeSet).order.Len(); n != config.DefaultHistorySeenMax {
			t.Errorf("a scope holds %d segments, want the cap %d", n, config.DefaultHistorySeenMax)
		}
		if got := s.fresh("k", segs[:10]); len(got) != 10 {
			t.Errorf("the oldest segments were not evicted: %d of 10 fresh", len(got))
		}
	})
	t.Run("scope-cap", func(t *testing.T) {
		var s historySeen
		for i := 0; i <= historySeenMaxScopes; i++ {
			s.record(fmt.Sprintf("k%d", i), []string{"a"}, allow, 0)
		}
		if len(s.scopes) != historySeenMaxScopes || s.order.Len() != historySeenMaxScopes {
			t.Errorf("%d scopes kept, want the cap %d", len(s.scopes), historySeenMaxScopes)
		}
		if got := s.fresh("k0", []string{"a"}); len(got) != 1 {
			t.Errorf("the least recently used scope was not dropped")
		}
	})
}
