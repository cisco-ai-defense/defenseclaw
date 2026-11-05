// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

type coworkMetricHealthSource struct {
	snapshot delivery.HealthSnapshot
}

func (source *coworkMetricHealthSource) DeliveryHealthSnapshot() delivery.HealthSnapshot {
	return source.snapshot
}

func TestDestinationHealthMetricExportCountsStaySignalScoped(t *testing.T) {
	for _, tc := range []struct {
		name   string
		secure bool
		want   delivery.Counters
	}{
		// The destination total covers logs and traces only, so it balances.
		{"standard profile", false, delivery.Counters{}},
		{"Secure Client twin", true, delivery.Counters{Accepted: 397, Delivered: 187, Rejected: 210}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dependencies := newRuntimeTestDependencies(t)
			plan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 30,
				func(source *config.ObservabilityV8Source) {
					yes := true
					source.Defaults.Collect.Metrics = &yes
					source.Destinations = []config.ObservabilityV8DestinationSource{{
						Name: "collector", Kind: config.ObservabilityV8DestinationOTLP,
						Protocol: "http/protobuf", Endpoint: "https://collector.example.test",
						Send: &config.ObservabilityV8SendSource{
							Signals: []observability.Signal{observability.SignalMetrics},
							Buckets: []observability.Bucket{"*"},
						},
					}}
				})
			healthSource := &coworkMetricHealthSource{snapshot: delivery.HealthSnapshot{
				Destination: "collector", Generation: 1, Signal: string(observability.SignalMetrics),
				State: delivery.HealthHealthy, Reason: string(delivery.HealthReasonRecovered),
				Counters: delivery.Counters{Accepted: 397, Delivered: 187, Rejected: 210},
			}}
			options := dependencies.options()
			options.SecureClient = tc.secure
			options.TelemetryProviderFactory = telemetry.NewV8ProviderFactory(telemetry.V8ProviderOptions{
				Version: "8.0.0", Environment: "test", ServiceInstanceID: "metric-health",
				GenerationPipelines: func(context.Context, *config.ObservabilityV8Plan, uint64,
					telemetry.V8MetricReaderSpec) (telemetry.V8GenerationPipelines, error) {
					return telemetry.V8GenerationPipelines{
						HealthSources: []delivery.SnapshotSource{healthSource},
					}, nil
				},
			})
			runtime, err := New(t.Context(), runtimegraph.ConfigFromPlan(plan, tc.secure), options)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if closeErr := runtime.Close(ctx); closeErr != nil {
					t.Errorf("close runtime: %v", closeErr)
				}
			})
			snapshot, err := runtime.DestinationHealthSnapshot(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			row := destinationHealthByName(t, snapshot, "collector")
			if row.Counters != tc.want || len(row.Sources) != 1 ||
				row.Sources[0].Signal != string(observability.SignalMetrics) ||
				row.Sources[0].Counters != (delivery.Counters{Accepted: 397, Delivered: 187, Rejected: 210}) {
				t.Fatalf("destination counters=%+v, metric source=%+v, want destination=%+v",
					row.Counters, row.Sources, tc.want)
			}
		})
	}
}
