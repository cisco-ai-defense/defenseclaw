// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"strings"
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
	block := &ScanVerdict{Action: "block", RuleIDs: []string{"DC-TEST-RULE"}}
	t.Run("miss-is-fresh", func(t *testing.T) {
		var s historySeen
		if got, _ := s.fresh("k", []string{"a", "b", "a"}); len(got) != 2 {
			t.Errorf("fresh on an empty record = %q, want a and b once", got)
		}
	})
	t.Run("unverified-records-nothing", func(t *testing.T) {
		var s historySeen
		s.record("", "", []string{"a"}, allow, false, false, 0)
		if got, _ := s.fresh("", []string{"a"}); len(got) != 1 {
			t.Errorf("an unverified caller skipped a segment: %q", got)
		}
	})
	t.Run("failed-judge-records-nothing", func(t *testing.T) {
		var s historySeen
		s.record("c", "k", []string{"a"}, &ScanVerdict{Action: "allow", JudgeFailed: true}, false, false, 0)
		if got, _ := s.fresh("k", []string{"a"}); len(got) != 1 {
			t.Errorf("a segment whose judge failed was skipped: %q", got)
		}
	})
	t.Run("degraded-allow-records-nothing", func(t *testing.T) {
		var s historySeen
		s.record("c", "k", []string{"a"}, allow, false, true, 0)
		if got, _ := s.fresh("k", []string{"a"}); len(got) != 1 {
			t.Errorf("a segment a degraded inspection allowed was skipped: %q", got)
		}
	})
	t.Run("degraded-refusal-is-recorded", func(t *testing.T) {
		var s historySeen
		s.record("c", "k", []string{"a"}, block, true, true, 0)
		if got, refused := s.fresh("k", []string{"a"}); len(got) != 0 || refused[historyHashOf("a")].rule != "DC-TEST-RULE" {
			t.Errorf("a refusal of a degraded inspection: fresh %q, refused %v", got, refused)
		}
	})
	t.Run("scopes-are-separate", func(t *testing.T) {
		var s historySeen
		s.record("c", "k1", []string{"a"}, allow, false, false, 0)
		if got, _ := s.fresh("k2", []string{"a"}); len(got) != 1 {
			t.Errorf("one scope's record skipped a segment of another: %q", got)
		}
		if got, refused := s.fresh("k1", []string{"a"}); len(got) != 0 || refused != nil {
			t.Errorf("a recorded allowed segment: fresh %q, refused %v", got, refused)
		}
	})
	t.Run("keeps-refused", func(t *testing.T) {
		var s historySeen
		s.record("c", "k", []string{"a"}, block, true, false, 0)
		s.record("c", "k", []string{"a"}, allow, false, false, 0)
		if _, refused := s.fresh("k", []string{"a"}); len(refused) != 1 {
			t.Errorf("a later allow cleared a refusal: %v", refused)
		}
	})
	t.Run("observe-block-is-not-refused", func(t *testing.T) {
		var s historySeen
		s.record("c", "k", []string{"a"}, &ScanVerdict{Action: "block"}, false, false, 0)
		if got, refused := s.fresh("k", []string{"a"}); len(got) != 0 || refused != nil {
			t.Errorf("a forwarded block verdict: fresh %q, refused %v", got, refused)
		}
	})
	t.Run("default-cap", func(t *testing.T) {
		var s historySeen
		segs := make([]string, config.DefaultHistorySeenMax+10)
		for i := range segs {
			segs[i] = fmt.Sprintf("seg-%d", i)
		}
		s.record("c", "k", segs, allow, false, false, 0)
		if n := s.scopes["k"].Value.(*historyScopeSet).order.Len(); n != config.DefaultHistorySeenMax {
			t.Errorf("a scope holds %d segments, want the cap %d", n, config.DefaultHistorySeenMax)
		}
		if got, _ := s.fresh("k", segs[:10]); len(got) != 10 {
			t.Errorf("the oldest segments were not evicted: %d of 10 fresh", len(got))
		}
	})
	t.Run("scope-cap", func(t *testing.T) {
		var s historySeen
		for i := 0; i <= historySeenMaxScopes; i++ {
			s.record(fmt.Sprintf("c%d", i), fmt.Sprintf("k%d", i), []string{"a"}, allow, false, false, 0)
		}
		if len(s.scopes) != historySeenMaxScopes || s.order.Len() != historySeenMaxScopes {
			t.Errorf("%d scopes kept, want the cap %d", len(s.scopes), historySeenMaxScopes)
		}
		if got, _ := s.fresh("k0", []string{"a"}); len(got) != 1 {
			t.Errorf("the least recently used scope was not dropped")
		}
	})
	t.Run("per-caller-cap", func(t *testing.T) {
		var s historySeen
		s.record("other", "other-session", []string{"a"}, allow, false, false, 0)
		for i := 0; i < 4*historySeenMaxScopesPerCaller; i++ {
			s.record("rotator", fmt.Sprintf("rot-%d", i), []string{"a"}, allow, false, false, 0)
		}
		if got, _ := s.fresh("other-session", []string{"a"}); len(got) != 0 {
			t.Errorf("a caller rotating sessions evicted another caller's record")
		}
		if n := s.perCaller["rotator"]; n != historySeenMaxScopesPerCaller {
			t.Errorf("the rotating caller holds %d scopes, want %d", n, historySeenMaxScopesPerCaller)
		}
		if got, _ := s.fresh(fmt.Sprintf("rot-%d", 4*historySeenMaxScopesPerCaller-1), []string{"a"}); len(got) != 0 {
			t.Errorf("the rotating caller lost its newest session")
		}
	})
}

// The redaction rewrites only the refused strings of the turn lists; the
// turns, roles, ids and every other field stay, repeated keys included.
func TestGAP0254RedactRefusedHistoryUnit(t *testing.T) {
	refused := map[historyHash]historyRefusal{historyHashOf("bad text"): {text: "bad text", rule: "R1"}}
	body := []byte(`{"model":"m","instructions":"bad text","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"bad text"}]},` +
		`{"type":"function_call","call_id":"c1","name":"read","arguments":"{}"},{"type":"function_call_output","call_id":"c1","output":"bad text"},` +
		`{"type":"message","role":"assistant","content":[{"type":"output_text","text":"ok"}]},{"type":"message","role":"user","content":"next"}]}`)
	out, reds, ok := redactRefusedHistory(body, 0, refused)
	if !ok || len(reds) != 2 || reds[0].Turn != 0 || reds[1].Turn != 2 || reds[0].Rule != "R1" {
		t.Fatalf("redactions = %+v, ok %v", reds, ok)
	}
	if strings.Count(string(out), "bad text") != 1 || !strings.Contains(string(out), `"instructions":"bad text"`) {
		t.Errorf("only the turn strings are replaced (instructions are the current scope): %s", out)
	}
	if !strings.Contains(string(out), `"call_id":"c1"`) || strings.Count(string(out), historyRedactedText) != 2 {
		t.Errorf("the turns lost a field: %s", out)
	}
	if strings.HasPrefix(historyRedactedText, defenseClawBlockBanner) {
		t.Errorf("the placeholder starts with the block banner, so laundering would drop the turn")
	}
	if _, _, ok := redactRefusedHistory([]byte(`{"input":[{"role":"user","content":"fine"}]}`), 0, refused); ok {
		t.Errorf("a body without a refused string reported a redaction")
	}
	if _, _, ok := redactRefusedHistory([]byte(`not json`), 0, refused); ok {
		t.Errorf("a body that is not JSON reported a redaction")
	}
}
