// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"testing"
	"time"
)

// rel-1-0-6:GAP-0550: building the per-IP limiter must not start a goroutine.
// Its old sweeper ticked forever, one per route table built, so a test binary
// that builds thousands of API servers kept thousands of them.
func TestPerIPRateLimiterOwnsNoGoroutine(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	before := runtime.NumGoroutine()
	handlers := make([]http.Handler, 0, 64)
	for i := 0; i < 64; i++ {
		handlers = append(handlers, perIPRateLimiter(20, 40)(next))
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

// The idle-entry bound still holds: a request after the sweep interval drops
// entries idle past the eviction age, and keeps the fresh ones.
func TestPerIPRateLimiterEvictsIdleEntriesOnARequest(t *testing.T) {
	var mu sync.Mutex
	clock := time.Unix(1_800_000_000, 0)
	now := func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	advance := func(d time.Duration) { mu.Lock(); clock = clock.Add(d); mu.Unlock() }
	sweeps, evicted := 0, 0
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	handler := newPerIPRateLimiter(1, 1, now, func(n int) { sweeps++; evicted += n })(next)
	request := func(remote string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool", nil)
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := request("192.0.2.10:4000"); code != http.StatusNoContent {
		t.Fatalf("first request = %d", code)
	}
	if code := request("192.0.2.10:4000"); code != http.StatusTooManyRequests {
		t.Fatalf("second request within the burst = %d, want 429", code)
	}
	advance(30 * time.Second)
	request("192.0.2.11:4000")
	if sweeps != 0 {
		t.Fatalf("swept %d times before the sweep interval", sweeps)
	}
	// 6 minutes later .10 and .11 are idle past the eviction age; the
	// request that triggers the sweep (.12) is added after it.
	advance(6 * time.Minute)
	if code := request("192.0.2.12:4000"); code != http.StatusNoContent {
		t.Fatalf("fresh caller = %d", code)
	}
	if sweeps != 1 || evicted != 2 {
		t.Fatalf("sweeps = %d evicted = %d, want 1 sweep dropping 2 idle entries", sweeps, evicted)
	}
	// No second sweep inside the interval, and the limiter still throttles.
	if code := request("192.0.2.12:4000"); code != http.StatusTooManyRequests {
		t.Fatalf("burst after the sweep = %d, want 429", code)
	}
	if sweeps != 1 {
		t.Fatalf("sweeps = %d inside one interval, want 1", sweeps)
	}
	if code := request("127.0.0.1:4000"); code != http.StatusNoContent {
		t.Fatalf("loopback = %d, want the bypass", code)
	}
}
