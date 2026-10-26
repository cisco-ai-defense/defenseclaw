// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"testing"
	"time"
)

// r103 GAP-0045: a Hermes config whose hooks block is rewritten every 200 ms
// must be repaired within 3 s of the first damaged write. The pass the burst
// arms runs by the shipped maximum wait; at 3 s the first repair audit came
// 3.9 s after the first write on macOS. The pass must start by 2 s, leaving
// a second for the reconcile and its audit.
func TestEnterpriseHookWatchRewriteBurstLeavesTimeForTheRepair(t *testing.T) {
	const debounce = 750 * time.Millisecond // the --debounce default
	first := time.Date(2026, 10, 17, 21, 22, 40, 0, time.UTC)
	var fireAt time.Time
	for at := time.Duration(0); at < 20*time.Second; at += 200 * time.Millisecond {
		now := first.Add(at)
		if !fireAt.IsZero() && !now.Before(fireAt) {
			break
		}
		fireAt = now.Add(enterpriseHookWatchDebounceDelay(now, first, debounce, enterpriseHookWatchDebounceMaxWait))
	}
	// The pass checks for its recheck window, then repairs and audits
	// (about 0.9 s on macOS, plus the worker start).
	if pass := fireAt.Sub(first) + enterpriseHookWatchRecheckFor("fsnotify"); pass > 1500*time.Millisecond {
		t.Fatalf("a 200 ms rewrite burst ends its check %s after the first write; the repair cannot land within 3 s", pass)
	}
}
