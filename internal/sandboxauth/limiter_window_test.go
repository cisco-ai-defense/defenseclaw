// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package sandboxauth

import (
	"testing"
	"time"
)

// A binding at its default limits is refused for its rate alone: every call
// the bucket admits (the burst, then the rate) may still be open for the
// longest request lifetime, and none of them may meet the open request bound
// (rel-1-0-6 GAP-0490: the bound was 32, then 128, and a valid call was
// refused 429 "too many concurrent" after 1.2 s).
func TestDefaultBindingBoundHoldsEveryCallTheRateAdmits(t *testing.T) {
	lifetime := MaxRequestLifetimeSeconds * time.Second
	for _, class := range []string{"hook", "receipt"} {
		t.Run(class, func(t *testing.T) {
			clock := newTestClock()
			cfg := DefaultLimiterConfig()
			cfg.Now = clock.Now
			l := NewLimiter(cfg)
			b := Binding{ID: "sb_window"}
			open, step := 0, 100*time.Millisecond
			for at := time.Duration(0); at < lifetime; at += step {
				clock.Advance(step)
				// Each step admits what the bucket holds: the burst at first,
				// then the refill. Nothing is released inside the lifetime.
				for {
					var err error
					if class == "receipt" {
						_, err = l.AcquireReceipt(b)
					} else {
						_, err = l.Acquire(b, RouteHook)
					}
					if err != nil {
						if err != ErrRateLimited {
							t.Fatalf("call %d after %v: %v, want the rate to be the only limit", open+1, at, err)
						}
						break
					}
					open++
				}
			}
			if want := DefaultHookBurst + DefaultHookRPS*MaxRequestLifetimeSeconds; open < want-DefaultHookRPS || open > want+DefaultHookRPS {
				t.Fatalf("%d calls were admitted over %v, want about %d", open, lifetime, want)
			}
		})
	}
}

// A binding still refuses what its bound does not cover: the open request
// bound stays in force above the rate.
func TestDefaultBindingBoundStillRefusesPastIt(t *testing.T) {
	cfg := DefaultLimiterConfig()
	cfg.HookRPS, cfg.HookBurst = 100000, 100000
	l := NewLimiter(cfg)
	b := Binding{ID: "sb_bound"}
	for i := 0; i < DefaultMaxInFlight; i++ {
		if _, err := l.Acquire(b, RouteHook); err != nil {
			t.Fatalf("call %d: %v", i+1, err)
		}
	}
	refuse(t, l, b, RouteHook, ErrTooManyInFlight)
}
