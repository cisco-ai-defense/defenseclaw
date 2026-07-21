// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	oteltrace "go.opentelemetry.io/otel/trace"
)

func TestInspectMetricsV8ExportCanonicalDashboardFamiliesWithoutLegacyProvider(t *testing.T) {
	api, capture := bindHookModelV8Runtime(t, []string{"metrics"})
	api.scannerCfg = &config.Config{Guardrail: config.GuardrailConfig{Connector: "codex"}}

	ctx := audit.ContextWithEnvelope(context.Background(), audit.CorrelationEnvelope{
		RunID: "run-inspect-1", RequestID: "request-inspect-1", SessionID: "session-inspect-1",
		TurnID: "turn-inspect-1", AgentID: "agent-inspect-1", PolicyID: "policy-inspect-1",
		DestinationApp: "mcp.example", ToolName: "write_file", ToolID: "tool-call-inspect-1",
	})
	spanContext := oteltrace.NewSpanContext(oteltrace.SpanContextConfig{
		TraceID: oteltrace.TraceID{1, 3, 5, 7}, SpanID: oteltrace.SpanID{2, 4, 6, 8},
		TraceFlags: oteltrace.FlagsSampled, Remote: true,
	})
	ctx = oteltrace.ContextWithRemoteSpanContext(ctx, spanContext)
	elapsed := 12*time.Millisecond + 500*time.Microsecond

	api.recordInspectMetricsV8(
		ctx, "CoDeX", "CoDeX:Write File", "allow", "NONE", elapsed,
	)
	api.recordGuardrailMetricsV8(
		ctx, "CoDeX", "CoDeX:policy-rules", "allow", elapsed,
	)
	api.emitCodeGuardTelemetry(ctx, &ToolInspectRequest{Tool: "write_file"}, &ToolInspectVerdict{
		Action: "allow", Severity: "NONE",
	}, elapsed)

	wants := map[string]int{
		observability.TelemetryInstrumentDefenseClawInspectEvaluations:   1,
		observability.TelemetryInstrumentDefenseClawInspectLatency:       1,
		observability.TelemetryInstrumentDefenseClawGuardrailEvaluations: 2,
		observability.TelemetryInstrumentDefenseClawGuardrailLatency:     2,
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_, requests := capture.snapshot()
		complete := true
		for name, want := range wants {
			if hookModelV8MetricPointCount(requests, name) < want {
				complete = false
				break
			}
		}
		if complete {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	traces, requests := capture.snapshot()
	if got := len(hookModelV8CapturedSpans(traces)); got != 0 {
		t.Fatalf("metrics-only destination received traces: %d", got)
	}
	for name, want := range wants {
		if got := hookModelV8MetricPointCount(requests, name); got != want {
			t.Errorf("metric %q points=%d want=%d", name, got, want)
		}
	}
	assertHookV8MetricPoint(t, hookModelV8MetricPoints(
		requests, observability.TelemetryInstrumentDefenseClawInspectEvaluations,
	), map[string]string{
		"defenseclaw.connector.source":  "codex",
		"defenseclaw.metric.action":     "allow",
		"defenseclaw.security.severity": "INFO",
		"defenseclaw.metric.tool":       "codex:write_file",
	}, 1)
	assertHookV8MetricPoint(t, hookModelV8MetricPoints(
		requests, observability.TelemetryInstrumentDefenseClawInspectLatency,
	), map[string]string{
		"defenseclaw.connector.source": "codex",
		"defenseclaw.metric.tool":      "codex:write_file",
	}, 12.5)
	guardrailPoints := hookModelV8MetricPoints(
		requests, observability.TelemetryInstrumentDefenseClawGuardrailEvaluations,
	)
	for _, scanner := range []string{"codex:policy-rules", "codeguard"} {
		assertHookV8MetricPoint(t, guardrailPoints, map[string]string{
			"defenseclaw.connector.source":           "codex",
			"defenseclaw.guardrail.effective_action": "allow",
			"defenseclaw.metric.guardrail.scanner":   scanner,
		}, 1)
	}
	guardrailLatency := hookModelV8MetricPoints(
		requests, observability.TelemetryInstrumentDefenseClawGuardrailLatency,
	)
	for _, scanner := range []string{"codex:policy-rules", "codeguard"} {
		assertHookV8MetricPoint(t, guardrailLatency, map[string]string{
			"defenseclaw.connector.source":         "codex",
			"defenseclaw.metric.guardrail.scanner": scanner,
		}, 12.5)
	}
}

func TestInspectMetricsV8DoNotFallBackWhenRuntimeIsUnbound(t *testing.T) {
	api := &APIServer{}
	api.recordInspectMetricsV8(
		context.Background(), "codex", "codex:shell", "block", "HIGH", time.Millisecond,
	)
	api.recordGuardrailMetricsV8(
		context.Background(), "codex", "codex:policy-rules", "block", time.Millisecond,
	)
}

func TestCodeGuardAlertMetricV8DoesNotDuplicateInspectEvaluation(t *testing.T) {
	api, capture := bindHookModelV8Runtime(t, []string{"metrics"})
	api.scannerCfg = &config.Config{Guardrail: config.GuardrailConfig{Connector: "codex"}}
	api.emitCodeGuardTelemetry(
		context.Background(),
		&ToolInspectRequest{Tool: "write_file"},
		&ToolInspectVerdict{
			Action: "alert", Severity: "HIGH", Findings: []string{"codeguard:CG-EXEC-001:Command execution"},
		},
		5*time.Millisecond,
	)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_, requests := capture.snapshot()
		if hookModelV8MetricPointCount(requests, observability.TelemetryInstrumentDefenseClawAlertCount) == 1 &&
			hookModelV8MetricPointCount(requests, observability.TelemetryInstrumentDefenseClawGuardrailEvaluations) == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	_, requests := capture.snapshot()
	if got := hookModelV8MetricPointCount(requests, observability.TelemetryInstrumentDefenseClawInspectEvaluations); got != 0 {
		t.Fatalf("CodeGuard alert duplicated inspect evaluation points=%d", got)
	}
	assertHookV8MetricPoint(t, hookModelV8MetricPoints(
		requests, observability.TelemetryInstrumentDefenseClawAlertCount,
	), map[string]string{
		"defenseclaw.connector.source":      "codex",
		"defenseclaw.metric.alert.severity": "HIGH",
		"defenseclaw.metric.alert.source":   "codeguard",
		"defenseclaw.metric.alert.type":     "codeguard-finding",
	}, 1)
}
