// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

func TestRecordCodexNotifyV8PreservesLabelsAndCorrelation(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	ctx := ContextWithSessionID(t.Context(), "session-codex")
	recordCodexNotifyV8(ctx, runtime, "agent-turn-complete", "completed", "ok", "turn-codex")

	metrics := generatedMetricByName(capture.metricSnapshot(), observability.TelemetryInstrumentDefenseClawCodexNotify)
	if len(metrics) != 1 {
		t.Fatalf("generated codex notify metrics=%d", len(metrics))
	}
	attributes := metrics[0].Attributes()
	correlation := metrics[0].CanonicalRecord().Correlation()
	if attributes["defenseclaw.metric.type"] != "agent-turn-complete" ||
		attributes["defenseclaw.metric.status"] != "completed" ||
		attributes["defenseclaw.metric.result"] != "ok" ||
		correlation.ConnectorID != "codex" || correlation.SessionID != "session-codex" ||
		correlation.TurnID != "turn-codex" {
		t.Fatalf("generated codex notify attributes=%v correlation=%+v", attributes, correlation)
	}
}

func TestRecordCodexNotifyV8EmitsMalformedCompanionWithoutLegacyFallback(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	recordCodexNotifyV8(t.Context(), runtime, "", "", "malformed", "")

	primary := generatedMetricByName(capture.metricSnapshot(), observability.TelemetryInstrumentDefenseClawCodexNotify)
	malformed := generatedMetricByName(capture.metricSnapshot(), observability.TelemetryInstrumentDefenseClawCodexNotifyMalformed)
	if len(primary) != 1 || len(malformed) != 1 ||
		primary[0].Attributes()["defenseclaw.metric.type"] != "unknown" ||
		malformed[0].Attributes()["defenseclaw.metric.type"] != "unknown" {
		t.Fatalf("generated malformed codex metrics primary=%v malformed=%v", primary, malformed)
	}
}
