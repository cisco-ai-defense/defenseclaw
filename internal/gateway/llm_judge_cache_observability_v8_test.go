// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

func TestJudgeVerdictCacheUsesCanonicalCorrelatedMetrics(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	ctx, parent := platformHealthCorrelatedContext(t)
	cache := NewJudgeVerdictCache(30*time.Second, runtime)

	if _, ok := cache.Get(ctx, "injection", "judge-model", "input", "prompt", "llm-judge-injection", "none"); ok {
		t.Fatal("empty verdict cache unexpectedly hit")
	}
	cache.Put("injection", "judge-model", "input", "prompt", &guardrail.VerdictSnapshot{Action: "block"})
	if _, ok := cache.Get(ctx, "injection", "judge-model", "input", "prompt", "llm-judge-injection", "none"); !ok {
		t.Fatal("populated verdict cache unexpectedly missed")
	}

	misses := generatedMetricByName(
		capture.metricSnapshot(), observability.TelemetryInstrumentDefenseClawGuardrailCacheMisses,
	)
	hits := generatedMetricByName(
		capture.metricSnapshot(), observability.TelemetryInstrumentDefenseClawGuardrailCacheHits,
	)
	if len(misses) != 1 || len(hits) != 1 {
		t.Fatalf("canonical cache metrics misses=%d hits=%d", len(misses), len(hits))
	}
	for name, metric := range map[string]struct {
		attributes  map[string]any
		wantVerdict string
	}{
		"miss": {attributes: misses[0].Attributes(), wantVerdict: "none"},
		"hit":  {attributes: hits[0].Attributes(), wantVerdict: "block"},
	} {
		if metric.attributes["defenseclaw.metric.cache"] != "verdict" ||
			metric.attributes["defenseclaw.scan.scanner"] != "llm-judge-injection" ||
			metric.attributes["defenseclaw.metric.ttl_bucket"] != "30s" ||
			metric.attributes["defenseclaw.metric.verdict"] != metric.wantVerdict {
			t.Fatalf("%s cache metric attributes=%v", name, metric.attributes)
		}
	}
	correlation := hits[0].CanonicalRecord().Correlation()
	if correlation.TraceID != parent.TraceID().String() || correlation.SpanID != parent.SpanID().String() ||
		correlation.RequestID != "request-platform" || correlation.SessionID != "session-platform" ||
		correlation.TurnID != "turn-platform" || correlation.AgentID != "agent-platform" ||
		correlation.ToolInvocationID != "tool-platform" || correlation.PolicyID != "policy-platform" ||
		correlation.ConnectorID != "codex" {
		t.Fatalf("canonical cache correlation=%+v", correlation)
	}
}
