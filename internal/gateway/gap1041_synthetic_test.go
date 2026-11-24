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

// substrate-1 GAP-1041 (RV-T6A): a sustained stall that does not overlap the
// windows of the calls behind the verdict does not explain it.
func TestGAP1041StallMustOverlapTheFailingCalls(t *testing.T) {
	p := &openLoopFlushProbe{}
	t0 := time.Now()
	for i := range 40 {
		gap1041Note(p, t0.Add(time.Duration(i)*115*time.Millisecond), 115*time.Millisecond)
	}
	stallEnd := t0.Add(40 * 115 * time.Millisecond)
	before := []openLoopSpan{{t0.Add(-10 * time.Second), t0.Add(-5 * time.Second)}}
	after := []openLoopSpan{{stallEnd.Add(time.Second), stallEnd.Add(4 * time.Second)}}
	during := []openLoopSpan{{t0.Add(time.Second), t0.Add(time.Second + openLoopWait)}}
	for _, kind := range []string{"slow", "unanswered"} {
		if p.stalled(kind, before) || p.stalled(kind, after) {
			t.Fatalf("%s: a stall outside the failing calls' windows counted", kind)
		}
		if !p.stalled(kind, during) {
			t.Fatalf("%s: a %v stall over the failing calls did not count", kind, stallEnd.Sub(t0))
		}
	}
	// The failing windows of a verdict.
	r := openLoopResult{calls: []openLoopCall{
		{issued: t0, elapsed: 10 * time.Millisecond, answered: true},
		{issued: t0.Add(time.Second), elapsed: 900 * time.Millisecond, answered: true},
		{issued: t0.Add(2 * time.Second), answered: false},
	}}
	if got := r.failingSpans("unanswered", 0); len(got) != 1 || !got[0].from.Equal(t0.Add(2*time.Second)) || got[0].to.Sub(got[0].from) != openLoopWait {
		t.Fatalf("unanswered spans %v", got)
	}
	if got := r.failingSpans("slow", 100*time.Millisecond); len(got) != 1 || !got[0].from.Equal(t0.Add(time.Second)) {
		t.Fatalf("slow spans %v", got)
	}
	if got := r.failingSpans("inconclusive", 0); got != nil {
		t.Fatalf("inconclusive spans %v", got)
	}
}
