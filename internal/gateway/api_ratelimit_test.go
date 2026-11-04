// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"testing"
	"time"
)

func limiterTestHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
}

func limiterRequest(t *testing.T, handler http.Handler, remote string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool", nil)
	req.RemoteAddr = remote
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Code
}

func limiterEntries(set *perIPLimiterSet) int {
	n := 0
	set.limiters.Range(func(_, _ interface{}) bool { n++; return true })
	return n
}

// rel-1-0-6:GAP-0550: building the per-IP limiter must not start a goroutine.
// Its old sweeper ticked forever, one per route table built, so a test binary
// that builds thousands of API servers kept thousands of them.
func TestPerIPRateLimiterOwnsNoGoroutine(t *testing.T) {
	before := runtime.NumGoroutine()
	handlers := make([]http.Handler, 0, 64)
	for i := 0; i < 64; i++ {
		handlers = append(handlers, perIPRateLimiter(20, 40)(limiterTestHandler()))
	}
	// Let any goroutine the constructor started get scheduled.
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if after := runtime.NumGoroutine(); after > before+8 {
		t.Fatalf("64 limiters left %d goroutines running (before %d)", after-before, before)
	}
	runtime.KeepAlive(handlers)
}

// The sweep is armed by the first remote entry, evicts entries idle past the
// eviction age, re-arms only while entries remain, and is never armed by
// loopback traffic.
func TestPerIPRateLimiterSweepArmsOnlyWhileEntriesRemain(t *testing.T) {
	var mu sync.Mutex
	clock := time.Unix(1_800_000_000, 0)
	var pending []func()
	sweeps, evicted, kept := 0, 0, 0
	set := newPerIPLimiterSet(1, 1, perIPLimiterOptions{
		now:      func() time.Time { mu.Lock(); defer mu.Unlock(); return clock },
		schedule: func(_ time.Duration, f func()) { mu.Lock(); pending = append(pending, f); mu.Unlock() },
		swept:    func(e, r int) { sweeps++; evicted += e; kept = r },
	})
	advance := func(d time.Duration) { mu.Lock(); clock = clock.Add(d); mu.Unlock() }
	fire := func() {
		mu.Lock()
		if len(pending) != 1 {
			mu.Unlock()
			t.Fatalf("pending sweeps = %d, want 1", len(pending))
		}
		f := pending[0]
		pending = nil
		mu.Unlock()
		f()
	}
	handler := set.middleware(limiterTestHandler())
	if code := limiterRequest(t, handler, "127.0.0.1:4000"); code != http.StatusNoContent || len(pending) != 0 {
		t.Fatalf("loopback = %d with %d sweeps armed, want the bypass and none", code, len(pending))
	}
	if code := limiterRequest(t, handler, "192.0.2.10:4000"); code != http.StatusNoContent {
		t.Fatalf("first request = %d", code)
	}
	if code := limiterRequest(t, handler, "192.0.2.10:4000"); code != http.StatusTooManyRequests {
		t.Fatalf("second request within the burst = %d, want 429", code)
	}
	limiterRequest(t, handler, "192.0.2.11:4000")
	if len(pending) != 1 {
		t.Fatalf("pending sweeps after three remote requests = %d, want 1", len(pending))
	}
	// Two minutes on, nothing is idle past five minutes: the sweep keeps both
	// entries and re-arms.
	advance(2 * time.Minute)
	fire()
	if sweeps != 1 || evicted != 0 || kept != 2 {
		t.Fatalf("first sweep: sweeps=%d evicted=%d kept=%d, want 1/0/2", sweeps, evicted, kept)
	}
	// .11 is refreshed; .10 goes idle past the age and is evicted.
	advance(4 * time.Minute)
	limiterRequest(t, handler, "192.0.2.11:4000")
	advance(2 * time.Minute)
	fire()
	if evicted != 1 || kept != 1 {
		t.Fatalf("second sweep: evicted=%d kept=%d, want 1/1", evicted, kept)
	}
	advance(6 * time.Minute)
	fire()
	if evicted != 2 || kept != 0 || limiterEntries(set) != 0 {
		t.Fatalf("last sweep: evicted=%d kept=%d entries=%d, want 2/0/0", evicted, kept, limiterEntries(set))
	}
	if len(pending) != 0 {
		t.Fatalf("an empty limiter re-armed its sweep (%d pending)", len(pending))
	}
	// A new remote caller arms it again.
	limiterRequest(t, handler, "192.0.2.12:4000")
	if len(pending) != 1 {
		t.Fatalf("pending sweeps after a new caller = %d, want 1", len(pending))
	}
}

// Review probe (rel-1-0-6:GAP-0550): idle remote entries expire while only
// loopback callers follow, and while no one calls at all, with real timers.
func TestPerIPRateLimiterIdleEntriesExpireWithoutRemoteTraffic(t *testing.T) {
	for _, loopback := range []bool{true, false} {
		t.Run(fmt.Sprintf("loopback=%v", loopback), func(t *testing.T) {
			set := newPerIPLimiterSet(20, 40, perIPLimiterOptions{
				idleEviction:  200 * time.Millisecond,
				sweepInterval: 100 * time.Millisecond,
			})
			handler := set.middleware(limiterTestHandler())
			for i := 1; i <= 100; i++ {
				if code := limiterRequest(t, handler, fmt.Sprintf("192.0.2.%d:4000", i)); code != http.StatusNoContent {
					t.Fatalf("request %d = %d", i, code)
				}
			}
			deadline := time.Now().Add(5 * time.Second)
			for limiterEntries(set) != 0 && time.Now().Before(deadline) {
				time.Sleep(100 * time.Millisecond)
				if loopback {
					limiterRequest(t, handler, "127.0.0.1:4000")
				}
			}
			if n := limiterEntries(set); n != 0 {
				t.Fatalf("idle entries left = %d, want 0", n)
			}
			set.mu.Lock()
			armed := set.armed
			set.mu.Unlock()
			if armed {
				t.Fatal("the sweep stays armed on an empty limiter")
			}
		})
	}
}
