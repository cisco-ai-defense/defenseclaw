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
func TestWatchdogRecordsWatcherRestart(t *testing.T) {
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())

	reader := sdkmetric.NewManualReader()
	prov, err := telemetry.NewProviderForTest(reader)
	if err != nil {
		t.Fatalf("NewProviderForTest: %v", err)
	}
	defer func() { _ = prov.Shutdown(context.Background()) }()

	var healthy atomic.Bool
	// Start UNhealthy. Loop will debounce into stateDown, then flip to healthy
	// so we cross the recovery edge exactly once.
	healthy.Store(false)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if healthy.Load() {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"gateway":{"state":"running"}}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	// Flip to healthy mid-loop so the watchdog sees the transition.
	go func() {
		time.Sleep(40 * time.Millisecond)
		healthy.Store(true)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	runWatchdogLoop(ctx, srv.URL+"/health", 10*time.Millisecond, 2, nil, prov)

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := counterValue(t, rm, "defenseclaw.watcher.restarts")
	if got < 1 {
		t.Fatalf("expected defenseclaw.watcher.restarts ≥ 1 after recovery, got %d", got)
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
