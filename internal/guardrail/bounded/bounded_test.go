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
	if trunc.Within(Depth, 9, 8) || !trunc.Set().Has(Depth) || trunc.Set().Has(Items) {
		t.Fatalf("past the cap: %+v", trunc.Set())
	}
}

func TestCounterTakesUpToItsMax(t *testing.T) {
	var trunc Truncated
	paths := NewCounter(&trunc, Paths, 3)
	for i := 0; i < 3; i++ {
		if !paths.Take() {
			t.Fatalf("take %d refused", i+1)
		}
	}
	if paths.Take() || !trunc.Set().Has(Paths) {
		t.Fatalf("4th take: trunc=%+v", trunc.Set())
	}
	var bytes Truncated
	size := NewCounter(&bytes, Bytes, 10)
	if !size.TakeN(10) || size.TakeN(1) || !bytes.Set().Has(Bytes) {
		t.Fatalf("bytes: %+v", bytes.Set())
	}
}

// A negative TakeN is a reader error, never a refund (review R5).
func TestCounterRefusesANegativeTake(t *testing.T) {
	var trunc Truncated
	size := NewCounter(&trunc, Bytes, 10)
	if size.TakeN(-1000) || !trunc.Set().Has(Bytes) {
		t.Fatalf("negative take: ok, set %+v", trunc.Set())
	}
	if size.TakeN(500) {
		t.Fatal("a negative take refunded 1000 bytes: 500 fit under a 10-byte cap")
	}
}

// A time cap counted in work units trips on the same input everywhere.
func TestTimeCapCountsWork(t *testing.T) {
	var trunc Truncated
	work := NewCounter(&trunc, Time, 100)
	visited := 0
	for range 1000 {
		if !work.Take() {
			break
		}
		visited++
	}
	if visited != 100 || !trunc.Set().Has(Time) {
		t.Fatalf("work budget 100: visited %d, set %+v", visited, trunc.Set())
	}
}

func TestBeforeRecordsTime(t *testing.T) {
	var trunc Truncated
	now := time.Unix(100, 0)
	if !trunc.Before(now, now.Add(time.Second)) || trunc.Any() {
		t.Fatal("a deadline ahead must not truncate")
	}
	if trunc.Before(now, now) || !trunc.Set().Has(Time) {
		t.Fatal("a deadline reached must record Time")
	}
	var unset Truncated
	if unset.Before(now, time.Time{}) || !unset.Set().Has(Time) {
		t.Fatal("a zero deadline (never set) must record Time, not pass silently")
	}
}

func TestReasonNamesEveryCapInOrder(t *testing.T) {
	if got := (CapSet{}).Reason(); got != "" {
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
	if len(Caps()) != int(capEnd)-1 {
		t.Fatalf("Caps() lists %d kinds, %d declared", len(Caps()), capEnd-1)
	}
	var unnamed Truncated
	unnamed.Hit(0)
	unnamed.Hit(capEnd + 3)
	if !unnamed.Set().Has(Items) || unnamed.Set().Union(Of(Bytes)) != Of(Items, Bytes) {
		t.Fatal("a cap with no kind must still truncate (as items)")
	}
	var merged Truncated
	merged.Merge(Of(Bytes))
	merged.Merge(Of(Depth))
	if merged.Set() != Of(Bytes, Depth) {
		t.Fatal("merge lost a cap")
	}
}

// The rule itself, over every base verdict, tier and cap: a truncated input
// is at least the unknown tier of the pack and never below its base; an
// untruncated one keeps its base.
func TestFloorIsAtLeastUnknownAndBase(t *testing.T) {
	for _, tier := range []Tier{TierDefault, TierPermissive, TierStrict} {
		for base := Allow; base <= Block; base++ {
			if got := Floor(base, CapSet{}, tier); got != base {
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
}

// Every spelling the gateway and its adopters emit is read; a name the floor
// cannot read is never lowered (review R1, GAP-0319).
func TestParseActionReadsEverySpelling(t *testing.T) {
	for in, want := range map[string]Action{
		"allow": Allow, "alert": Alert, "confirm": Confirm, "ask": Confirm, "block": Block,
		"BLOCK": Block, "Block": Block, " block": Block, "block\t": Block, "ALERT": Alert, "": Allow,
	} {
		if got, known := ParseAction(in); got != want || !known {
			t.Errorf("ParseAction(%q) = %s known=%t, want %s", in, got, known, want)
		}
	}
	for _, in := range []string{"deny", "observe", "blocked", "allowx"} {
		if got, known := ParseAction(in); got != Block || known {
			t.Errorf("ParseAction(%q) = %s known=%t, want block (never lowered) and unknown", in, got, known)
		}
	}
	for a := Allow; a <= Block; a++ {
		if got, _ := ParseAction(a.String()); got != a {
			t.Fatalf("action %d does not round-trip", a)
		}
	}
}

// The hot path (counting, checking, merging, the floor) allocates nothing.
func TestHotPathAllocatesNothing(t *testing.T) {
	now := time.Unix(100, 0)
	allocs := testing.AllocsPerRun(1000, func() {
		var trunc Truncated
		items := NewCounter(&trunc, Items, 64)
		for i := 0; i < 80; i++ {
			if !items.Take() {
				break
			}
		}
		_ = trunc.Within(Depth, 9, 8)
		_ = trunc.Before(now, now.Add(time.Second))
		trunc.Merge(Of(Bytes))
		_ = trunc.Set().Has(Items)
		_, _ = ParseAction(" Block")
		_ = Floor(Allow, trunc.Set(), TierDefault)
	})
	if allocs != 0 {
		t.Fatalf("hot path allocated %.0f times per run", allocs)
	}
}

func BenchmarkCounterTake(b *testing.B) {
	b.ReportAllocs()
	var trunc Truncated
	items := NewCounter(&trunc, Items, 1<<30)
	for b.Loop() {
		_ = items.Take()
	}
}
