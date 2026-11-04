// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
)

func TestObservabilityV8StatusExplainsCounterScope(t *testing.T) {
	for _, tc := range []struct {
		name           string
		separateMetric bool
		want           delivery.Counters
	}{
		{"standard profile", true, delivery.Counters{}},
		{"Secure Client twin", false, delivery.Counters{Accepted: 397, Delivered: 187, Rejected: 210}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			destination := observabilityruntime.DestinationHealth{
				Name: "collector", Kind: config.ObservabilityV8DestinationOTLP, Enabled: true,
				Signals:             []observability.Signal{observability.SignalMetrics},
				State:               delivery.HealthHealthy,
				MetricExportsScoped: tc.separateMetric,
				Counters:            tc.want,
				Sources: []delivery.HealthSnapshot{{
					Destination: "collector", Generation: 1, Signal: string(observability.SignalMetrics),
					State:    delivery.HealthHealthy,
					Counters: delivery.Counters{Accepted: 397, Delivered: 187, Rejected: 210},
				}},
			}
			health := renderObservabilityV8Health(time.Time{},
				observabilityruntime.DestinationHealthSnapshot{
					Generation: 1, Destinations: []observabilityruntime.DestinationHealth{destination},
				}, nil, "", "", 0, observabilityV8EventHistorySnapshot{})
			rows, ok := health.Details["destinations"].([]map[string]interface{})
			if !ok || len(rows) != 1 {
				t.Fatalf("destination details=%+v", health.Details)
			}
			row := rows[0]
			counters, ok := row["counters"].(map[string]interface{})
			if !ok || counters["accepted"] != tc.want.Accepted || counters["delivered"] != tc.want.Delivered ||
				counters["rejected"] != tc.want.Rejected {
				t.Fatalf("destination counters=%+v", row["counters"])
			}
			signals, ok := row["signal_health"].([]map[string]interface{})
			if !ok || len(signals) != 1 || signals[0]["counters"].(map[string]interface{})["rejected"] != uint64(210) {
				t.Fatalf("signal health=%+v", row["signal_health"])
			}
			_, documented := row["counters_scope"]
			if documented != tc.separateMetric {
				t.Fatalf("counter scope documented=%t, want %t", documented, tc.separateMetric)
			}
		})
	}
}
