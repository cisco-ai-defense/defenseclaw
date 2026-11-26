// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package testenv

import (
	"testing"
	"time"
)

// HoldsUnderBar passes a leg whose one slow hold clears on a second run,
// and fails a leg that is slow in its median or whose worst hold is over its
// window in every run.
func TestHoldsUnderBarSeparatesAHostTailFromASlowProduct(t *testing.T) {
	t.Setenv(ScaleEnv, "1")
	ms := func(n int) time.Duration { return time.Duration(n) * time.Millisecond }
	leg := func(slowHolds ...time.Duration) []time.Duration {
		holds := make([]time.Duration, 20)
		for i := range holds {
			holds[i] = ms(12)
		}
		copy(holds, slowHolds)
		return holds
	}
	for _, tc := range []struct {
		name string
		runs [][]time.Duration
		want bool
	}{
		{"every hold under the bar", [][]time.Duration{leg()}, true},
		{"one tail, clean second run", [][]time.Duration{leg(ms(225)), leg()}, true},
		{"one tail, tail again, clean third run", [][]time.Duration{leg(ms(225)), leg(ms(602)), leg()}, true},
		{"a tail that stays in the second window", [][]time.Duration{leg(ms(650)), leg(ms(450))}, true},
		{"worst hold over every window", [][]time.Duration{leg(ms(2000)), leg(ms(2000)), leg(ms(2000))}, false},
		{"every pass takes the slow path", [][]time.Duration{leg(ms(230), ms(230), ms(230), ms(230), ms(230), ms(230), ms(230), ms(230), ms(230), ms(230), ms(230), ms(230))}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next := 0
			holds, ok, report := HoldsUnderBar(ms(200), func() []time.Duration {
				run := tc.runs[min(next, len(tc.runs)-1)]
				next++
				return run
			})
			if ok != tc.want {
				t.Fatalf("ok = %v, want %v after %d runs:\n%s", ok, tc.want, next, report)
			}
			if len(holds) != 20 {
				t.Fatalf("holds of the deciding run = %d, want 20", len(holds))
			}
			if tc.name == "every pass takes the slow path" && next != 1 {
				t.Fatalf("a slow median must fail at once, measured %d runs", next)
			}
		})
	}
}
