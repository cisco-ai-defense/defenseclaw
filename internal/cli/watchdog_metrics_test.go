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

package cli

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

type recordingWatchdogRecovery struct {
	attempts atomic.Int64
	recorded atomic.Int64
	failures atomic.Int64
}

func (recorder *recordingWatchdogRecovery) RecordWatchdogRecovery(context.Context) error {
	recorder.attempts.Add(1)
	for {
		remaining := recorder.failures.Load()
		if remaining <= 0 {
			recorder.recorded.Add(1)
			return nil
		}
		if recorder.failures.CompareAndSwap(remaining, remaining-1) {
			return errors.New("injected recovery failure")
		}
	}
}

func TestWatchdogAPIRecoveryRecorderUsesAuthenticatedCSRFProtectedPost(t *testing.T) {
	const token = "watchdog-test-token"
	called := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/watchdog/recovery" ||
			r.Header.Get("Authorization") != "Bearer "+token ||
			r.Header.Get("X-DefenseClaw-Client") != "watchdog" ||
			r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("recovery request method/path/headers=%s %s %v", r.Method, r.URL.Path, r.Header)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		called <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	recorder := &watchdogAPIRecoveryRecorder{
		client: server.Client(), url: server.URL + "/api/v1/watchdog/recovery", token: token,
	}
	if err := recorder.RecordWatchdogRecovery(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-called:
	default:
		t.Fatal("recovery endpoint was not called")
	}
}

// TestWatchdogRecordsWatcherRestart pins the Track-7 contract for Issue #96:
// on a real down→healthy transition the watchdog MUST bump
// defenseclaw.watcher.restarts so operators can alert on flapping sidecars
// without scraping stderr. Before this fix the counter was defined but never
// incremented; this test fails if the wiring regresses.
//
// The previous version of this test wall-clocked the flip from "unhealthy"
// to "healthy" 40ms after the loop started and gave the loop only 200ms to
// observe both transitions. On a loaded test runner the first probe can
// take 30+ms (DNS + httptest server warm-up + Go's TLS-less HTTP machinery),
// which compressed the post-flip observation window below the
// debounce-then-recover requirement and produced an ~5% flake rate. The
// rewrite below removes the wall-clock dependency entirely:
//
//   - Probe count, not elapsed time, drives the flip — once the loop has
//     done at least `debounce` failed probes (so it is definitely in
//     stateDown), the test marks the server healthy and waits for the
//     recovery counter to land via a polling assertion.
//   - The deadline is 5s purely as an upper bound for "the build server
//     is wedged"; a healthy run completes in tens of milliseconds.
func TestWatchdogRecordsWatcherRestart(t *testing.T) {
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())

	recorder := &recordingWatchdogRecovery{}
	recorder.failures.Store(2)

	var (
		healthy atomic.Bool
		probes  atomic.Int64
	)
	// Start UNhealthy. Loop will debounce into stateDown, then we flip to
	// healthy so it crosses the recovery edge exactly once.
	healthy.Store(false)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		probes.Add(1)
		if healthy.Load() {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"gateway":{"state":"running"}}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	// Drive the flip off the actual probe count, not a sleep. We need at
	// least `debounce` (=2) failed probes before the loop is allowed to
	// move into stateDown, plus one more so we are certain the down edge
	// has been observed by the watchdog before we flip the server
	// healthy. After that, the very next probe should see stateHealthy
	// and increment the restart counter.
	const debounce = 2
	go func() {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if probes.Load() >= debounce+1 {
				healthy.Store(true)
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	loopDone := make(chan struct{})
	go func() {
		runWatchdogLoop(ctx, srv.URL+"/health", 10*time.Millisecond, debounce, nil, recorder)
		close(loopDone)
	}()

	// Poll the canonical-sidecar acknowledgement rather than wait for
	// runWatchdogLoop to return —
	// the loop only exits on ctx cancellation, but our assertion needs
	// just one observed recovery.
	deadline := time.Now().Add(3 * time.Second)
	for {
		if recorder.recorded.Load() >= 1 {
			cancel()
			<-loopDone
			if recorder.attempts.Load() < 3 {
				t.Fatalf("recovery notification was not retried: attempts=%d", recorder.attempts.Load())
			}
			return
		}
		if time.Now().After(deadline) {
			cancel()
			<-loopDone
			t.Fatalf("expected canonical watcher recovery acknowledgement after transition "+
				"(attempts=%d probes=%d healthy=%v)", recorder.attempts.Load(), probes.Load(), healthy.Load())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestWatchdogDoesNotRecordRestartOnSteadyHealthy guards against a noisy
// counter: the watchdog must only bump defenseclaw.watcher.restarts on an
// actual state transition, never on every healthy probe.
func TestWatchdogDoesNotRecordRestartOnSteadyHealthy(t *testing.T) {
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())

	recorder := &recordingWatchdogRecovery{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"gateway":{"state":"running"}}`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()

	runWatchdogLoop(ctx, srv.URL+"/health", 10*time.Millisecond, 2, nil, recorder)

	if got := recorder.attempts.Load(); got != 0 {
		t.Fatalf("expected 0 recovery notifications during steady healthy window, got %d", got)
	}
}
