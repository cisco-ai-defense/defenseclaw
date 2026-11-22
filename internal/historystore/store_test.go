// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package historystore

import (
	"context"
	"fmt"
	"testing"
)

func h(i int) Hash {
	var out Hash
	copy(out[:], fmt.Sprintf("%016d", i))
	return out
}

func TestProcessSeenAndRecord(t *testing.T) {
	ctx := context.Background()
	var p Process
	if got, err := p.Seen(ctx, "s", []Hash{h(1)}); err != nil || got != nil {
		t.Fatalf("an empty store holds %v (%v)", got, err)
	}
	_ = p.Record(ctx, "c", "s", []Hash{h(1), h(2)}, Entry{Verdict: Allowed}, 8)
	_ = p.Record(ctx, "c", "s", []Hash{h(2)}, Entry{Verdict: Refused, Rule: "R1"}, 8)
	_ = p.Record(ctx, "c", "s", []Hash{h(2)}, Entry{Verdict: Allowed}, 8)
	got, _ := p.Seen(ctx, "s", []Hash{h(1), h(2), h(3)})
	if len(got) != 2 || got[h(1)].Verdict != Allowed || got[h(2)] != (Entry{Verdict: Refused, Rule: "R1"}) {
		t.Errorf("seen = %v: want h1 allowed, h2 refused by R1 (a later allow does not lower it), h3 absent", got)
	}
	if got, _ := p.Seen(ctx, "other", []Hash{h(1)}); got != nil {
		t.Errorf("one scope's record answered another: %v", got)
	}
	// The per-scope cap drops the least recently used hash: Seen made h(1)
	// the most recent, so h(2) goes.
	_, _ = p.Seen(ctx, "s", []Hash{h(1)})
	_ = p.Record(ctx, "c", "s", []Hash{h(3)}, Entry{}, 2)
	got, _ = p.Seen(ctx, "s", []Hash{h(1), h(2), h(3)})
	if _, dropped := got[h(2)]; len(got) != 2 || dropped {
		t.Errorf("after a cap of 2: %v, want h1 and h3", got)
	}
	if _, n, _ := p.Stats("s", "c"); n != 2 {
		t.Errorf("the scope holds %d hashes, want 2", n)
	}
}

func TestProcessScopeBounds(t *testing.T) {
	ctx := context.Background()
	var p Process
	_ = p.Record(ctx, "other", "keep", []Hash{h(1)}, Entry{}, 8)
	for i := 0; i < 4*MaxScopesPerCaller; i++ {
		_ = p.Record(ctx, "rotator", fmt.Sprintf("rot-%d", i), []Hash{h(1)}, Entry{}, 8)
	}
	if _, _, n := p.Stats("", "rotator"); n != MaxScopesPerCaller {
		t.Errorf("a caller holds %d scopes, want %d", n, MaxScopesPerCaller)
	}
	if got, _ := p.Seen(ctx, "keep", []Hash{h(1)}); len(got) != 1 {
		t.Error("a caller rotating sessions dropped another caller's scope")
	}
	for i := 0; i <= MaxScopes; i++ {
		_ = p.Record(ctx, fmt.Sprintf("c%d", i), fmt.Sprintf("k%d", i), []Hash{h(1)}, Entry{}, 8)
	}
	if n, _, _ := p.Stats("", ""); n != MaxScopes {
		t.Errorf("%d scopes kept, want the cap %d", n, MaxScopes)
	}
}
