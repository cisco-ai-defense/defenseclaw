// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows && !race

package gateway

import (
	"testing"
	"time"
)

// gap1041Note records one synthetic probe flush.
func gap1041Note(p *openLoopFlushProbe, at time.Time, took time.Duration) {
	p.note(at, took, nil)
}

// substrate-1 GAP-1041: a sustained stall explains a timing verdict only over
// the calls it overlaps. Slow calls before or after it stay in the judgement
// and fail it; slow calls during it are set aside and the rest pass.
func TestGAP1041StallMustOverlapTheFailingCalls(t *testing.T) {
	p := &openLoopFlushProbe{}
	t0 := time.Now()
	for i := range 40 {
		gap1041Note(p, t0.Add(time.Duration(i)*115*time.Millisecond), 115*time.Millisecond)
	}
	stallEnd := t0.Add(40 * 115 * time.Millisecond)
	stream := func(from time.Time, kind string) *openLoopTiming {
		r := openLoopResult{}
		for i := range 30 {
			c := openLoopCall{issued: from.Add(time.Duration(i) * 100 * time.Millisecond), elapsed: 900 * time.Millisecond, answered: kind == "slow"}
			r.calls = append(r.calls, c)
		}
		for i := range 200 {
			c := openLoopCall{issued: t0.Add(time.Duration(i-100) * 100 * time.Millisecond), elapsed: 10 * time.Millisecond, answered: true}
			if openLoopAnyOverlap(openLoopSpan{c.issued, c.issued.Add(c.elapsed)}, []openLoopSpan{{from, from.Add(3 * time.Second)}}) {
				continue
			}
			r.calls = append(r.calls, c)
		}
		r.offered = len(r.calls)
		for _, c := range r.calls {
			if c.answered {
				r.latencies = append(r.latencies, c.elapsed)
			}
		}
		return &openLoopTiming{r, 100 * time.Millisecond}
	}
	for _, kind := range []string{"slow", "unanswered"} {
		for _, from := range []time.Time{t0.Add(-8 * time.Second), stallEnd.Add(2 * time.Second)} {
			if ok, why := p.explains(kind, stream(from, kind)); ok {
				t.Fatalf("%s: a stall outside the failing calls' windows explained them: %s", kind, why)
			}
		}
		if ok, why := p.explains(kind, stream(t0.Add(time.Second), kind)); !ok {
			t.Fatalf("%s: a %v stall over the failing calls did not explain them: %s", kind, stallEnd.Sub(t0), why)
		}
		if ok, _ := p.explains(kind, nil); ok {
			t.Fatalf("%s: a timing verdict with no stream to judge again was explained", kind)
		}
	}
	if ok, _ := p.explains("inconclusive", nil); !ok {
		t.Fatal("a sustained stall did not explain an inconclusive verdict")
	}
	// The windows set aside: an answered call's wait, an unanswered call's
	// answer window.
	r := openLoopResult{offered: 4, calls: []openLoopCall{
		{issued: t0, elapsed: 10 * time.Millisecond, answered: true},
		{issued: t0.Add(time.Second), elapsed: 900 * time.Millisecond, answered: true},
		{issued: t0.Add(2 * time.Second), answered: false},
	}}
	rest, left := r.without([]openLoopSpan{{t0.Add(1500 * time.Millisecond), t0.Add(1600 * time.Millisecond)}})
	if left != 1 || rest.offered != 3 || len(rest.calls) != 2 || len(rest.latencies) != 1 {
		t.Fatalf("without a span inside the slow call: left %d, rest %+v", left, rest)
	}
	rest, left = r.without([]openLoopSpan{{t0.Add(5 * time.Second), t0.Add(5100 * time.Millisecond)}})
	if left != 1 || rest.offered != 3 || len(rest.latencies) != 2 {
		t.Fatalf("without a span inside the unanswered call's window: left %d, rest %+v", left, rest)
	}
}
