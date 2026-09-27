// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package sandboxauth

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestLimiterBurstRefillAndIsolation(t *testing.T) {
	clock := newFakeNow()
	l := NewLimiter(LimiterConfig{HookRPS: 2, HookBurst: 3, OTLPRPS: 1, OTLPBurst: 1, MaxInFlight: 100, Now: clock.Now})
	a := Binding{ID: "sb_a"}
	b := Binding{ID: "sb_b"}
	for i := 0; i < 3; i++ {
		release, err := l.Acquire(a, RouteHook)
		if err != nil {
			t.Fatalf("hook %d: %v", i, err)
		}
		release()
	}
	if _, err := l.Acquire(a, RouteHook); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("burst exhausted: %v", err)
	}
	// Another binding has its own bucket.
	if release, err := l.Acquire(b, RouteHook); err != nil {
		t.Fatalf("other binding throttled: %v", err)
	} else {
		release()
	}
	// OTLP has its own bucket, so telemetry cannot starve hooks and hooks
	// cannot starve telemetry.
	if release, err := l.Acquire(a, RouteOTLP); err != nil {
		t.Fatalf("otlp bucket shared with hooks: %v", err)
	} else {
		release()
	}
	if _, err := l.Acquire(a, RouteOTLP); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("otlp burst exhausted: %v", err)
	}
	clock.Advance(500 * time.Millisecond)
	if release, err := l.Acquire(a, RouteHook); err != nil {
		t.Fatalf("bucket did not refill: %v", err)
	} else {
		release()
	}
}

func TestLimiterInFlightCap(t *testing.T) {
	l := NewLimiter(LimiterConfig{HookRPS: 1000, HookBurst: 1000, MaxInFlight: 2})
	b := Binding{ID: "sb_a"}
	r1, err := l.Acquire(b, RouteHook)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := l.Acquire(b, RouteInspect)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Acquire(b, RouteNotify); !errors.Is(err, ErrTooManyInFlight) {
		t.Fatalf("cap not enforced: %v", err)
	}
	r1()
	r1() // idempotent
	if r3, err := l.Acquire(b, RouteHook); err != nil {
		t.Fatalf("slot not returned: %v", err)
	} else {
		r3()
	}
	r2()
}

// TestLimiterOTLPHasItsOwnSlots pins that telemetry uploads, which may each
// pin a large body, can neither take the slots hooks need nor grow without
// bound per binding or across bindings.
func TestLimiterOTLPHasItsOwnSlots(t *testing.T) {
	l := NewLimiter(LimiterConfig{
		HookRPS: 1000, HookBurst: 1000, OTLPRPS: 1000, OTLPBurst: 1000,
		MaxInFlight: 1, OTLPMaxInFlight: 2, OTLPMaxInFlightTotal: 3,
	})
	a, b, c := Binding{ID: "sb_a"}, Binding{ID: "sb_b"}, Binding{ID: "sb_c"}
	var releases []func()
	acquire := func(binding Binding, route Route) {
		t.Helper()
		release, err := l.Acquire(binding, route)
		if err != nil {
			t.Fatalf("%s %s: %v", binding.ID, route, err)
		}
		releases = append(releases, release)
	}
	acquire(a, RouteOTLP)
	acquire(a, RouteOTLP)
	if _, err := l.Acquire(a, RouteOTLP); !errors.Is(err, ErrTooManyInFlight) {
		t.Fatalf("per-binding otlp cap: %v", err)
	}
	// Open uploads do not hold the hook slot.
	acquire(a, RouteHook)
	if _, err := l.Acquire(a, RouteHook); !errors.Is(err, ErrTooManyInFlight) {
		t.Fatalf("hook cap: %v", err)
	}
	// A full hook slot does not block telemetry of another binding, but the
	// cross-binding total does.
	acquire(b, RouteOTLP)
	if _, err := l.Acquire(c, RouteOTLP); !errors.Is(err, ErrTooManyInFlight) {
		t.Fatalf("total otlp cap: %v", err)
	}
	if r, err := l.Acquire(c, RouteHook); err != nil {
		t.Fatalf("hooks limited by the otlp total: %v", err)
	} else {
		r()
	}
	// A forgotten binding's open upload still returns its share of the total.
	l.Forget(a.ID)
	releases[0]()
	if r, err := l.Acquire(c, RouteOTLP); err != nil {
		t.Fatalf("total not returned after forget: %v", err)
	} else {
		r()
	}
	for _, release := range releases {
		release()
	}
	l.mu.Lock()
	total := l.otlpTotal
	l.mu.Unlock()
	if total != 0 {
		t.Fatalf("otlp total = %d after every release", total)
	}
}

func TestLimiterBindingOverride(t *testing.T) {
	l := NewLimiter(LimiterConfig{HookRPS: 1000, HookBurst: 1000, MaxInFlight: 100})
	b := Binding{ID: "sb_a", RateLimit: RateLimit{RequestsPerSecond: 1, Burst: 1, MaxInFlight: 1}}
	release, err := l.Acquire(b, RouteHook)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Acquire(b, RouteHook); !errors.Is(err, ErrTooManyInFlight) {
		t.Fatalf("override cap: %v", err)
	}
	// A changed override rebuilds the buckets but keeps the open request.
	b.RateLimit = RateLimit{RequestsPerSecond: 10, Burst: 10, MaxInFlight: 1}
	if _, err := l.Acquire(b, RouteHook); !errors.Is(err, ErrTooManyInFlight) {
		t.Fatalf("override change reset the concurrency cap: %v", err)
	}
	release()
	if r, err := l.Acquire(b, RouteHook); err != nil {
		t.Fatalf("after release: %v", err)
	} else {
		r()
	}
}

func TestLimiterForgetAndSweep(t *testing.T) {
	clock := newFakeNow()
	l := NewLimiter(LimiterConfig{HookRPS: 1, HookBurst: 1, IdleTTL: time.Minute, Now: clock.Now})
	b := Binding{ID: "sb_a"}
	r, err := l.Acquire(b, RouteHook)
	if err != nil {
		t.Fatal(err)
	}
	r()
	if _, err := l.Acquire(b, RouteHook); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("expected throttle: %v", err)
	}
	l.Forget(b.ID)
	if r, err := l.Acquire(b, RouteHook); err != nil {
		t.Fatalf("forget did not reset state: %v", err)
	} else {
		r()
	}
	clock.Advance(2 * time.Minute)
	if r, err := l.Acquire(Binding{ID: "sb_b"}, RouteHook); err != nil {
		t.Fatal(err)
	} else {
		r()
	}
	l.mu.Lock()
	_, stillThere := l.bindings[b.ID]
	l.mu.Unlock()
	if stillThere {
		t.Fatal("idle binding state was not swept")
	}
}

func TestInFlightQuiescence(t *testing.T) {
	clock := newFakeNow()
	f := NewInFlight(clock.Now)
	if !f.Quiescent("sb_a", time.Second) || f.Active("sb_a") != 0 || !f.LastActivity("sb_a").IsZero() {
		t.Fatal("unknown binding must be quiescent")
	}
	end1 := f.Begin("sb_a")
	end2 := f.Begin("sb_a")
	if f.Active("sb_a") != 2 || f.Quiescent("sb_a", 0) {
		t.Fatal("open requests are not quiescent")
	}
	end1()
	end1()
	if f.Active("sb_a") != 1 {
		t.Fatalf("end not idempotent: %d", f.Active("sb_a"))
	}
	end2()
	if f.Quiescent("sb_a", time.Second) {
		t.Fatal("just-finished request must wait out the idle interval")
	}
	clock.Advance(time.Second)
	if !f.Quiescent("sb_a", time.Second) {
		t.Fatal("idle interval elapsed")
	}
	if !f.Quiescent("sb_other", time.Hour) {
		t.Fatal("bindings are independent")
	}
	f.Forget("sb_a")
	if !f.LastActivity("sb_a").IsZero() {
		t.Fatal("forget kept state")
	}
}

func TestInFlightWaitQuiescent(t *testing.T) {
	f := NewInFlight(nil)
	end := f.Begin("sb_a")
	done := make(chan error, 1)
	go func() { done <- f.WaitQuiescent(context.Background(), "sb_a", 20*time.Millisecond) }()
	select {
	case err := <-done:
		t.Fatalf("returned while a request was open: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	start := time.Now()
	end()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
		if elapsed := time.Since(start); elapsed < 15*time.Millisecond {
			t.Fatalf("returned before the idle interval: %v", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("WaitQuiescent never returned")
	}

	f.Begin("sb_b")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := f.WaitQuiescent(ctx, "sb_b", 0); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancelled wait = %v", err)
	}
}
