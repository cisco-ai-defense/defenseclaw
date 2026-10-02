// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
)

// GAP-1774: a MEDIUM alert decision is counted with action=alert and
// severity=MEDIUM, and its log record carries severity_text MEDIUM (WARN
// band), not INFO.
func TestHookDecisionV8AlertKeepsSeverityInMetricsAndLog(t *testing.T) {
	api, capture := bindHookModelV8Runtime(t, []string{"logs", "metrics"})
	ctx := audit.ContextWithEnvelope(context.Background(), audit.CorrelationEnvelope{
		RunID: "run-alert-1", RequestID: "request-alert-1", SessionID: "session-alert-1",
	})
	req := agentHookRequest{
		ConnectorName: "claudecode", HookEventName: "PreToolUse", SessionID: "session-alert-1", ToolName: "Bash",
	}
	resp := agentHookResponse{
		Action: "alert", RawAction: "alert", Severity: "MEDIUM", Mode: "action",
		RuleIDs: []string{"PATH-SSH-KEY"}, EvaluationID: "evaluation-alert-1",
	}
	api.emitHookDecisionObservabilityV8(ctx, req, resp, HookAuditEnvelope{ElapsedMs: 3}, false)

	name := observability.TelemetryInstrumentDefenseClawConnectorHookOutcome
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_, requests := capture.snapshot()
		if hookModelV8MetricPointCount(requests, name) >= 1 && len(hookModelV8CapturedLogs(capture.logSnapshot())) >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	_, requests := capture.snapshot()
	assertHookV8MetricPoint(t, hookModelV8MetricPoints(requests, name), map[string]string{
		"defenseclaw.connector.source": "claudecode", "defenseclaw.metric.event_type": "tool_call",
		"defenseclaw.metric.action": "alert", "defenseclaw.security.severity": "MEDIUM",
		"defenseclaw.metric.would_block": "false",
	}, 1)
	logs := hookModelV8CapturedLogs(capture.logSnapshot())
	if len(logs) != 1 || logs[0].GetSeverityText() != "MEDIUM" ||
		logs[0].GetSeverityNumber() != logspb.SeverityNumber_SEVERITY_NUMBER_WARN {
		for _, record := range logs {
			t.Logf("log severity_text=%q number=%v", record.GetSeverityText(), record.GetSeverityNumber())
		}
		t.Fatalf("alert hook decision logs=%d, want one MEDIUM/WARN record", len(logs))
	}
}
