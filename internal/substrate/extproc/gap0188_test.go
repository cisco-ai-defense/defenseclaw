// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package extproc

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

// GAP-0188: when the leader can't answer, the registration lookup fails as
// well as the chain check. Past the uid cache (cache_ttl = stale_max = 60 s
// by default, so nothing is ever served stale), the actor's attendance must
// not be lost: the last known registration still decides, and an actor
// with none (a callout restart during the outage, an actor first seen in
// it) counts as unattended, so OSS chain.failure_mode auto refuses its
// unchecked egress, retryable (R4's proofs).

func outageHarness(t *testing.T, unattended bool) (*harness, *time.Time) {
	t.Helper()
	h := newHarness(t, func(_ *Config, o *Options) { o.ChainChecker = fakeChecker{err: errors.New("leader down")} })
	if h.uids.uid == "" {
		h.uids.uid = "25a1da0f-1c9b-4ef7-8248-c276138c7f77"
	}
	h.uids.unattended = unattended
	clock := time.Now()
	h.eng.uids.now = func() time.Time { return clock }
	return h, &clock
}

func leaderDown(h *harness) {
	h.uids.mu.Lock()
	h.uids.err = errors.New("leader down")
	h.uids.mu.Unlock()
}

func TestUnattendedActorWhenTheLeaderIsDownGAP0188(t *testing.T) {
	ctx := context.Background()
	h, clock := outageHarness(t, true)
	if v := h.eng.DecideHeaders(ctx, req("eng-web", "GET", "example.com", "/")); v.Allow {
		t.Fatalf("lookup up, chain down: unattended allowed: %+v", v)
	}
	leaderDown(h)
	start := *clock
	for _, after := range []time.Duration{30 * time.Second, 61 * time.Second, 5 * time.Minute} {
		*clock = start.Add(after)
		v := h.eng.DecideHeaders(ctx, req("eng-web", "GET", "example.com", "/"))
		if v.Allow || v.Category != CategoryChainUnchecked || !v.Retryable {
			t.Fatalf("leader down %s: %+v", after, v)
		}
	}
}

func TestUnknownAttendanceCountsAsUnattendedGAP0188(t *testing.T) {
	h, _ := outageHarness(t, false)
	leaderDown(h) // a callout restart during the outage: nothing cached
	v := h.eng.DecideHeaders(context.Background(), req("eng-web", "GET", "example.com", "/"))
	if v.Allow || v.Category != CategoryChainUnchecked || !v.Retryable || !slices.Contains(v.Findings, "attendance_unknown") {
		t.Fatalf("unknown attendance during an outage: %+v", v)
	}
}

// An attended actor the callout knows keeps OSS auto's alert past the
// stale window (balanced defaults); its profile is the registration's.
func TestKnownAttendedActorKeepsTheAlertGAP0188(t *testing.T) {
	ctx := context.Background()
	h, clock := outageHarness(t, false)
	if v := h.eng.DecideHeaders(ctx, req("eng-web", "GET", "example.com", "/")); !v.Allow {
		t.Fatalf("lookup up, chain down: attended refused: %+v", v)
	}
	leaderDown(h)
	*clock = clock.Add(5 * time.Minute)
	v := h.eng.DecideHeaders(ctx, req("eng-web", "GET", "example.com", "/"))
	if !v.Allow || !v.Alert || slices.Contains(v.Findings, "attendance_unknown") ||
		!slices.Contains(v.Findings, "chain_unchecked:"+uncheckedLookup) {
		t.Fatalf("known attended actor during an outage: %+v", v)
	}
}
