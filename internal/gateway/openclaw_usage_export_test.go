// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

func TestOpenClawUsageMetricsFromResponse(t *testing.T) {
	raw := []byte(`{
		"aggregates": {
			"byModel": [{
				"provider": "openai",
				"model": "gpt-5.4",
				"count": 1543,
				"totals": {
					"input": 10000000,
					"output": 5000000,
					"cacheRead": 1000,
					"cacheWrite": 2000,
					"totalTokens": 15003000,
					"totalCost": 17.38
				}
			}],
			"messages": {
				"assistant": 1543,
				"errors": 1402,
				"toolCalls": 55,
				"total": 3055,
				"user": 1492
			},
			"tools": {
				"totalCalls": 55,
				"uniqueTools": 6
			},
			"latency": {
				"avgMs": 12.5,
				"p95Ms": 45.5,
				"maxMs": 120
			}
		}
	}`)

	metrics := openclawUsageMetricsFromResponse(raw)
	if len(metrics) == 0 {
		t.Fatal("expected usage metrics")
	}

	tokens := requireUsageMetric(t, metrics, "openclaw.tokens", "openai", "gpt-5.4")
	if tokens.value != 15003000 {
		t.Fatalf("openclaw.tokens value = %v, want 15003000", tokens.value)
	}
	if tokens.unit != "tokens" || tokens.tokenType != "total" || tokens.component != "openclaw_usage_rpc" || tokens.temporality != "snapshot" || tokens.sourceSignal != "openclaw_rpc" {
		t.Fatalf("openclaw.tokens labels = unit=%q tokenType=%q component=%q temporality=%q sourceSignal=%q",
			tokens.unit, tokens.tokenType, tokens.component, tokens.temporality, tokens.sourceSignal)
	}

	cost := requireUsageMetric(t, metrics, "openclaw.cost.usd", "openai", "gpt-5.4")
	if cost.value != 17.38 || cost.unit != "usd" {
		t.Fatalf("openclaw.cost.usd = %v %q, want 17.38 usd", cost.value, cost.unit)
	}

	errors := requireUsageMetric(t, metrics, "openclaw.messages.errors", "openclaw", "all")
	if errors.value != 1402 {
		t.Fatalf("openclaw.messages.errors = %v, want 1402", errors.value)
	}

	tools := requireUsageMetric(t, metrics, "openclaw.tool.calls", "openclaw", "all")
	if tools.value != 55 {
		t.Fatalf("openclaw.tool.calls = %v, want 55", tools.value)
	}
}

func requireUsageMetric(t *testing.T, metrics []otelDashboardMetric, name, provider, model string) otelDashboardMetric {
	t.Helper()
	for _, metric := range metrics {
		if metric.metricName == name && metric.provider == provider && metric.model == model {
			return metric
		}
	}
	t.Fatalf("metric %s provider=%s model=%s not found in %#v", name, provider, model, metrics)
	return otelDashboardMetric{}
}
