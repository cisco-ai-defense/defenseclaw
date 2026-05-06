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

package sinks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// newTestSink builds a SplunkHECSink pointed at the given test server
// URL with fast retry/circuit settings so tests don't sleep long.
func newTestSink(t *testing.T, serverURL string, overrides ...func(*SplunkHECConfig)) *SplunkHECSink {
	t.Helper()
	cfg := SplunkHECConfig{
		Name:                    "test",
		Endpoint:                serverURL,
		Token:                   "test-token",
		BatchSize:               10,
		FlushIntervalS:          0, // disable background ticker in tests
		TimeoutS:                2,
		MaxRetries:              3,
		RetryBaseDelayS:         0, // no sleep in unit tests
		CircuitBreakerThreshold: 5,
		CircuitBreakerCooldownS: 1, // 1 s cooldown for fast circuit tests
	}
	for _, o := range overrides {
		o(&cfg)
	}
	s, err := NewSplunkHECSink(cfg)
	if err != nil {
		t.Fatalf("NewSplunkHECSink: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TestRetry_SucceedsOnThirdAttempt verifies that sendWithRetry retries
// after transient failures and succeeds when the server recovers.
func TestRetry_SucceedsOnThirdAttempt(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := newTestSink(t, srv.URL)
	err := s.sendWithRetry(context.Background(), []byte(`{"event":"test"}`))
	if err != nil {
		t.Fatalf("expected success on third attempt, got: %v", err)
	}
	if got := calls.Load(); got != 3 {
		t.Errorf("expected 3 HTTP calls, got %d", got)
	}
	if state := s.CircuitState(); state != "closed" {
		t.Errorf("expected circuit closed after success, got %q", state)
	}
}

// TestRetry_ExhaustedReturnsError verifies that after MaxRetries+1 failures
// an error is returned and the batch is not silently dropped.
func TestRetry_ExhaustedReturnsError(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	s := newTestSink(t, srv.URL, func(c *SplunkHECConfig) {
		c.MaxRetries = 2 // 3 total attempts
		c.CircuitBreakerThreshold = 999 // don't open circuit mid-test
	})

	err := s.sendWithRetry(context.Background(), []byte(`{"event":"test"}`))
	if err == nil {
		t.Fatal("expected error after exhausted retries, got nil")
	}
	if got := calls.Load(); got != 3 {
		t.Errorf("expected 3 HTTP calls (1 + 2 retries), got %d", got)
	}
}

// TestCircuitBreaker_OpensAfterThreshold verifies the circuit opens
// after CircuitBreakerThreshold consecutive all-retry-exhausted failures.
func TestCircuitBreaker_OpensAfterThreshold(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	s := newTestSink(t, srv.URL, func(c *SplunkHECConfig) {
		c.MaxRetries = 0              // 1 attempt per sendWithRetry call
		c.CircuitBreakerThreshold = 3 // open after 3 failures
		c.CircuitBreakerCooldownS = 60
	})

	// First 3 calls should fail with a send error (circuit still closed).
	for i := 0; i < 3; i++ {
		if state := s.CircuitState(); state != "closed" {
			t.Fatalf("call %d: expected circuit closed before threshold, got %q", i, state)
		}
		_ = s.sendWithRetry(context.Background(), []byte(`{}`))
	}

	// Circuit should now be open.
	if state := s.CircuitState(); state != "open" {
		t.Fatalf("expected circuit open after threshold, got %q", state)
	}

	// Next call should be rejected immediately without hitting the server.
	err := s.sendWithRetry(context.Background(), []byte(`{}`))
	if err == nil {
		t.Fatal("expected error from open circuit, got nil")
	}
}

// TestCircuitBreaker_HalfOpenProbeSuccessCloses verifies that after the
// cooldown the circuit moves to half-open, a successful probe closes it,
// and normal sends resume.
func TestCircuitBreaker_HalfOpenProbeSuccessCloses(t *testing.T) {
	var recover atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if recover.Load() {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer srv.Close()

	s := newTestSink(t, srv.URL, func(c *SplunkHECConfig) {
		c.MaxRetries = 0
		c.CircuitBreakerThreshold = 2
		c.CircuitBreakerCooldownS = 1 // 1 second so tests stay fast
	})

	// Trip the circuit.
	for i := 0; i < 2; i++ {
		_ = s.sendWithRetry(context.Background(), []byte(`{}`))
	}
	if state := s.CircuitState(); state != "open" {
		t.Fatalf("expected circuit open, got %q", state)
	}

	// Wait for cooldown, then signal server to recover.
	time.Sleep(1100 * time.Millisecond)
	recover.Store(true)

	// This send should be the half-open probe that closes the circuit.
	err := s.sendWithRetry(context.Background(), []byte(`{}`))
	if err != nil {
		t.Fatalf("probe send failed: %v", err)
	}
	if state := s.CircuitState(); state != "closed" {
		t.Errorf("expected circuit closed after successful probe, got %q", state)
	}
}

// TestCircuitBreaker_HalfOpenProbeFailureReopens verifies that a failed
// probe re-opens the circuit and resets the cooldown timer.
func TestCircuitBreaker_HalfOpenProbeFailureReopens(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	s := newTestSink(t, srv.URL, func(c *SplunkHECConfig) {
		c.MaxRetries = 0
		c.CircuitBreakerThreshold = 2
		c.CircuitBreakerCooldownS = 1
	})

	// Trip the circuit.
	for i := 0; i < 2; i++ {
		_ = s.sendWithRetry(context.Background(), []byte(`{}`))
	}

	// Wait for cooldown so circuit goes half-open.
	time.Sleep(1100 * time.Millisecond)

	// Probe fails — circuit should re-open.
	_ = s.sendWithRetry(context.Background(), []byte(`{}`))
	if state := s.CircuitState(); state != "open" {
		t.Errorf("expected circuit re-opened after failed probe, got %q", state)
	}
}

// TestFlush_RequeuesOnFailure verifies that Flush puts events back into
// the batch when sendWithRetry fails, so they are retried on the next flush.
func TestFlush_RequeuesOnFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	s := newTestSink(t, srv.URL, func(c *SplunkHECConfig) {
		c.MaxRetries = 0
		c.CircuitBreakerThreshold = 999
	})

	// Manually seed the batch.
	s.mu.Lock()
	s.batch = append(s.batch, splunkEvent{Source: "test", Event: "payload"})
	s.mu.Unlock()

	_ = s.Flush(context.Background())

	// The event should be re-queued.
	s.mu.Lock()
	requeued := len(s.batch)
	s.mu.Unlock()

	if requeued == 0 {
		t.Error("expected event to be re-queued after flush failure, batch is empty")
	}
}

// TestRetry_ContextCancelledDuringBackoff verifies that context cancellation
// during the backoff sleep is respected and an error is returned promptly.
func TestRetry_ContextCancelledDuringBackoff(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	s := newTestSink(t, srv.URL, func(c *SplunkHECConfig) {
		c.MaxRetries = 3
		c.RetryBaseDelayS = 10 // long enough that ctx cancel fires first
		c.CircuitBreakerThreshold = 999
	})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := s.sendWithRetry(ctx, []byte(`{}`))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error on context cancellation, got nil")
	}
	// Should have returned well under the full retry delay.
	if elapsed > 2*time.Second {
		t.Errorf("context cancellation took too long: %v", elapsed)
	}
}
