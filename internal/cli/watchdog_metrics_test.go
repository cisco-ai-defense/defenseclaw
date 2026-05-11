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
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

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

	reader := sdkmetric.NewManualReader()
	prov, err := telemetry.NewProviderForTest(reader)
	if err != nil {
		t.Fatalf("NewProviderForTest: %v", err)
	}
	defer func() { _ = prov.Shutdown(context.Background()) }()

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
		runWatchdogLoop(ctx, srv.URL+"/health", 10*time.Millisecond, debounce, nil, prov)
		close(loopDone)
	}()

	// Poll the counter rather than wait for runWatchdogLoop to return —
	// the loop only exits on ctx cancellation, but our assertion needs
	// just one observed recovery.
	deadline := time.Now().Add(3 * time.Second)
	for {
		var rm metricdata.ResourceMetrics
		if err := reader.Collect(context.Background(), &rm); err != nil {
			t.Fatalf("Collect: %v", err)
		}
		if got := counterValue(t, rm, "defenseclaw.watcher.restarts"); got >= 1 {
			cancel()
			<-loopDone
			return
		}
		if time.Now().After(deadline) {
			cancel()
			<-loopDone
			t.Fatalf("expected defenseclaw.watcher.restarts ≥ 1 after recovery, got 0 "+
				"(probes=%d, healthy=%v)", probes.Load(), healthy.Load())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestWatchdogDoesNotRecordRestartOnSteadyHealthy guards against a noisy
// counter: the watchdog must only bump defenseclaw.watcher.restarts on an
// actual state transition, never on every healthy probe.
func TestWatchdogDoesNotRecordRestartOnSteadyHealthy(t *testing.T) {
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())

	reader := sdkmetric.NewManualReader()
	prov, err := telemetry.NewProviderForTest(reader)
	if err != nil {
		t.Fatalf("NewProviderForTest: %v", err)
	}
	defer func() { _ = prov.Shutdown(context.Background()) }()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"gateway":{"state":"running"}}`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()

	runWatchdogLoop(ctx, srv.URL+"/health", 10*time.Millisecond, 2, nil, prov)

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	if got := counterValue(t, rm, "defenseclaw.watcher.restarts"); got != 0 {
		t.Fatalf("expected 0 restarts during steady healthy window, got %d", got)
	}
}

func counterValue(t *testing.T, rm metricdata.ResourceMetrics, name string) int64 {
	t.Helper()
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("metric %s: expected Sum[int64], got %T", name, m.Data)
			}
			var total int64
			for _, dp := range sum.DataPoints {
				total += dp.Value
			}
			return total
		}
	}
	return 0
}
