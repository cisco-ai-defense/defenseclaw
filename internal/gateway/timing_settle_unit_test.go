// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"
	"time"
)

// One stalled measurement passes when a later one is within the limit; a
// slowdown that every measurement shows still fails (rel-1-0-10:GAP-1809).
func TestSettledTimeToleratesOneStalledMeasurementButNotARealSlowdown(t *testing.T) {
	const limit = 1250 * time.Millisecond
	seq := func(ds ...time.Duration) func() time.Duration {
		return func() time.Duration { d := ds[0]; ds = ds[1:]; return d }
	}
	// The run of PR 1488: 1.283 s once, then the row's usual 0.7 s.
	if got, used := settledTime(3, limit, seq(1283*time.Millisecond, 700*time.Millisecond)); got != 700*time.Millisecond || used != 2 {
		t.Fatalf("a stalled first measurement: got %s after %d, want 700ms after 2", got, used)
	}
	if got, used := settledTime(3, limit, seq(900*time.Millisecond)); got != 900*time.Millisecond || used != 1 {
		t.Fatalf("a measurement within the limit: got %s after %d, want 900ms after 1", got, used)
	}
	got, used := settledTime(3, limit, seq(1400*time.Millisecond, 1300*time.Millisecond, 1500*time.Millisecond))
	if got != 1300*time.Millisecond || used != 3 || got <= limit {
		t.Fatalf("a real slowdown: got %s after %d, want the best, 1.3s, after 3, over the limit", got, used)
	}
	if got, used := settledTime(1, limit, seq(1283*time.Millisecond)); got != 1283*time.Millisecond || used != 1 {
		t.Fatalf("one attempt: got %s after %d", got, used)
	}
}
