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

//go:build !windows

package sandboxauth

import (
	"context"
	"errors"
	"testing"
	"time"
)

// admit takes one slot and returns it at once, failing when the limiter refuses.
func admit(t *testing.T, l *Limiter, b Binding, route Route) {
	t.Helper()
	release, err := l.Acquire(b, route)
	if err != nil {
		t.Fatalf("Acquire(%s, %s): %v", b.ID, route, err)
	}
	release()
}

// refuse checks that the limiter turns a request away with want.
func refuse(t *testing.T, l *Limiter, b Binding, route Route, want error) {
	t.Helper()
	if _, err := l.Acquire(b, route); !errors.Is(err, want) {
		t.Fatalf("Acquire(%s, %s) = %v, want %v", b.ID, route, err, want)
	}
}

func TestLimiterBurstRefillAndIsolation(t *testing.T) {
	clock := newTestClock()
	l := NewLimiter(LimiterConfig{HookRPS: 2, HookBurst: 3, OTLPRPS: 1, OTLPBurst: 1, MaxInFlight: 100, Now: clock.Now})
	a, b := Binding{ID: "sb_a"}, Binding{ID: "sb_b"}
	for i := 0; i < 3; i++ {
		admit(t, l, a, RouteHook)
	}
	refuse(t, l, a, RouteHook, ErrRateLimited)
	admit(t, l, b, RouteHook) // another binding has its own bucket
	// OTLP has its own bucket, so telemetry and hooks cannot starve each other.
	admit(t, l, a, RouteOTLP)
	refuse(t, l, a, RouteOTLP, ErrRateLimited)
	clock.Advance(500 * time.Millisecond)
	admit(t, l, a, RouteHook)
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
	refuse(t, l, b, RouteNotify, ErrTooManyInFlight)
	r1()
	r1() // idempotent
	admit(t, l, b, RouteHook)
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
	hold := func(binding Binding, route Route) {
		t.Helper()
		release, err := l.Acquire(binding, route)
		if err != nil {
			t.Fatalf("%s %s: %v", binding.ID, route, err)
		}
		releases = append(releases, release)
	}
	hold(a, RouteOTLP)
	hold(a, RouteOTLP)
	refuse(t, l, a, RouteOTLP, ErrTooManyInFlight) // per-binding otlp cap
	// Open uploads do not hold the hook slot.
	hold(a, RouteHook)
	refuse(t, l, a, RouteHook, ErrTooManyInFlight)
	// A full hook slot does not block telemetry of another binding, but the
	// cross-binding total does, and it never limits hooks.
	hold(b, RouteOTLP)
	refuse(t, l, c, RouteOTLP, ErrTooManyInFlight)
	admit(t, l, c, RouteHook)
	// A forgotten binding's open upload still returns its share of the total.
	l.Forget(a.ID)
	releases[0]()
	admit(t, l, c, RouteOTLP)
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
	refuse(t, l, b, RouteHook, ErrTooManyInFlight)
	// A changed override rebuilds the buckets but keeps the open request.
	b.RateLimit = RateLimit{RequestsPerSecond: 10, Burst: 10, MaxInFlight: 1}
	refuse(t, l, b, RouteHook, ErrTooManyInFlight)
	release()
	admit(t, l, b, RouteHook)
}

func TestLimiterForgetAndSweep(t *testing.T) {
	clock := newTestClock()
	l := NewLimiter(LimiterConfig{HookRPS: 1, HookBurst: 1, IdleTTL: time.Minute, Now: clock.Now})
	b := Binding{ID: "sb_a"}
	admit(t, l, b, RouteHook)
	refuse(t, l, b, RouteHook, ErrRateLimited)
	l.Forget(b.ID)
	admit(t, l, b, RouteHook)
	clock.Advance(2 * time.Minute)
	admit(t, l, Binding{ID: "sb_b"}, RouteHook)
	l.mu.Lock()
	_, stillThere := l.bindings[b.ID]
	l.mu.Unlock()
	if stillThere {
		t.Fatal("idle binding state was not swept")
	}
}

func TestInFlightQuiescence(t *testing.T) {
	clock := newTestClock()
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
