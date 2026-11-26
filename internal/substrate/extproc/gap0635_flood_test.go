// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package extproc

import (
	"context"
	"testing"
	"time"
)

// TestGAP0635FloodFromOneActorIsRefused is substrate-1:GAP-0635 with the
// shipped default: 1,000 requests of one actor in the same instant to an
// allowed host are not all forwarded (the default budget is 200 a second,
// burst 400), and the refusals say rate_limited.
func TestGAP0635FloodFromOneActorIsRefused(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	h := newHarness(t, func(_ *Config, o *Options) { o.Now = func() time.Time { return now } })
	allowed, limited := 0, 0
	for range 1000 {
		v := h.eng.DecideHeaders(context.Background(), req("other", "GET", "example.com", "/"))
		switch {
		case v.Allow:
			allowed++
		case v.Category == "rate_limited":
			limited++
		}
	}
	if allowed != 400 || limited != 600 {
		t.Fatalf("%d allowed, %d rate_limited of 1000 (want 400, 600)", allowed, limited)
	}
}
