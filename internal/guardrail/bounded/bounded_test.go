// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package bounded

import (
	"testing"
	"time"
)

func TestWithinRecordsTheCapPastItsMax(t *testing.T) {
	var trunc Truncated
	if !trunc.Within(Depth, 8, 8) || trunc.Any() {
		t.Fatalf("at the cap: truncated=%v", trunc.Any())
	}
	if trunc.Within(Depth, 9, 8) || !trunc.Has(Depth) || trunc.Has(Items) {
		t.Fatalf("past the cap: %+v", trunc)
	}
}

func TestCounterTakesUpToItsMax(t *testing.T) {
	var trunc Truncated
	paths := NewCounter(Paths, 3)
	for i := 0; i < 3; i++ {
		if !paths.Take(&trunc) {
			t.Fatalf("take %d refused", i+1)
		}
	}
	if paths.Take(&trunc) || !trunc.Has(Paths) || paths.Count() != 4 {
		t.Fatalf("4th take: trunc=%+v count=%d", trunc, paths.Count())
	}
	var bytes Truncated
	size := NewCounter(Bytes, 10)
	if !size.TakeN(10, &bytes) || size.TakeN(1, &bytes) || !bytes.Has(Bytes) {
		t.Fatalf("bytes: %+v", bytes)
	}
}

func TestBeforeRecordsTime(t *testing.T) {
	var trunc Truncated
	now := time.Unix(100, 0)
	if !trunc.Before(now, time.Time{}) || !trunc.Before(now, now.Add(time.Second)) || trunc.Any() {
		t.Fatal("deadline ahead or unset must not truncate")
	}
	if trunc.Before(now, now) || !trunc.Has(Time) {
		t.Fatal("deadline reached must record Time")
	}
}

func TestReasonNamesEveryCapInOrder(t *testing.T) {
	if got := (Truncated{}).Reason(); got != "" {
		t.Fatalf("untruncated reason %q", got)
	}
	got := Of(Nodes, Paths, Depth).Reason()
	if want := "bounded_truncated cap=depth,paths,nodes"; got != want {
		t.Fatalf("reason %q want %q", got, want)
	}
	all := Of(Caps()...)
	for _, c := range Caps() {
		if !all.Has(c) || c.String() == "unknown" {
			t.Fatalf("cap %d: has=%t name=%q", c, all.Has(c), c.String())
		}
	}
	var unnamed Truncated
	unnamed.Hit(0)
	if !unnamed.Any() {
		t.Fatal("a cap with no kind must still truncate")
	}
	var merged Truncated
	merged.Merge(Of(Bytes))
	if !merged.Has(Bytes) {
		t.Fatal("merge lost a cap")
	}
}

// The rule itself, over every base verdict, tier and cap: a truncated input
// is at least the unknown tier and never below its base; an untruncated one
// keeps its base.
func TestFloorIsAtLeastUnknownAndBase(t *testing.T) {
	for _, tier := range []Tier{TierDefault, TierPermissive, TierStrict} {
		for base := Allow; base <= Block; base++ {
			if got := Floor(base, Truncated{}, tier); got != base {
				t.Fatalf("tier %d base %s untruncated: %s", tier, base, got)
			}
			for _, c := range Caps() {
				got := Floor(base, Of(c), tier)
				if got < base || got < Unknown(tier) {
					t.Fatalf("tier %d base %s cap %s: %s", tier, base, c, got)
				}
			}
		}
	}
	if Unknown(TierDefault) != Alert || Unknown(TierPermissive) != Alert || Unknown(TierStrict) != Block {
		t.Fatal("unknown tier: default/permissive alert, strict block")
	}
	for posture, want := range map[string]Tier{"strict": TierStrict, "permissive": TierPermissive,
		"default": TierDefault, "": TierDefault, "custom": TierDefault} {
		if got := TierOf(posture); got != want {
			t.Fatalf("TierOf(%q) = %d, want %d", posture, got, want)
		}
	}
	for a := Allow; a <= Block; a++ {
		if ParseAction(a.String()) != a {
			t.Fatalf("action %d does not round-trip", a)
		}
	}
	if ParseAction("") != Allow || ParseAction("observe") != Allow {
		t.Fatal("an unknown action name is allow")
	}
}

// The hot path (counting, checking, the floor) allocates nothing.
func TestHotPathAllocatesNothing(t *testing.T) {
	allocs := testing.AllocsPerRun(1000, func() {
		var trunc Truncated
		items := NewCounter(Items, 64)
		for i := 0; i < 80; i++ {
			if !items.Take(&trunc) {
				break
			}
		}
		_ = trunc.Within(Depth, 9, 8)
		_ = Floor(Allow, trunc, TierDefault)
	})
	if allocs != 0 {
		t.Fatalf("hot path allocated %.0f times per run", allocs)
	}
}

func BenchmarkCounterTake(b *testing.B) {
	b.ReportAllocs()
	var trunc Truncated
	items := NewCounter(Items, 1<<30)
	for b.Loop() {
		_ = items.Take(&trunc)
	}
}
