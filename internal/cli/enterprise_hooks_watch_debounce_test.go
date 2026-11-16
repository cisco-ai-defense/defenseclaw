// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"testing"
	"time"
)

// GAP-0532: every filesystem event re-armed the guardian's debounce with no
// limit, so a stream of writes faster than the debounce held the pass back
// until the interval pass. The delay now never runs past the burst's
// maximum wait.
func TestEnterpriseHookWatchDebounceDelayIsBoundedByTheBurst(t *testing.T) {
	const debounce, maxWait = 750 * time.Millisecond, 3 * time.Second
	first := time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name    string
		elapsed time.Duration
		want    time.Duration
	}{
		{"first event", 0, debounce},
		{"early in the burst", time.Second, debounce},
		{"near the bound", 2600 * time.Millisecond, 400 * time.Millisecond},
		{"at the bound", maxWait, 0},
		{"past the bound", 10 * time.Second, 0},
	} {
		if got := enterpriseHookWatchDebounceDelay(first.Add(tc.elapsed), first, debounce, maxWait); got != tc.want {
			t.Fatalf("%s: delay %s, want %s", tc.name, got, tc.want)
		}
	}
	if got := enterpriseHookWatchDebounceDelay(first, time.Time{}, debounce, maxWait); got != debounce {
		t.Fatalf("unarmed burst: delay %s, want %s", got, debounce)
	}
	if got := enterpriseHookWatchDebounceDelay(first.Add(time.Hour), first, debounce, 0); got != debounce {
		t.Fatalf("no bound: delay %s, want %s", got, debounce)
	}
	// A burst of events every 500 ms (each before the debounce fires) still
	// reaches its pass by the bound.
	var fireAt time.Time
	for at := time.Duration(0); at < 10*time.Second; at += 500 * time.Millisecond {
		now := first.Add(at)
		if !fireAt.IsZero() && !now.Before(fireAt) {
			break
		}
		fireAt = now.Add(enterpriseHookWatchDebounceDelay(now, first, debounce, maxWait))
	}
	if fireAt.Sub(first) > maxWait {
		t.Fatalf("a steady burst postponed the pass by %s, past %s", fireAt.Sub(first), maxWait)
	}
}
