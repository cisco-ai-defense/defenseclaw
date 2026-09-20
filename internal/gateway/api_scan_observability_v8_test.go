// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"go.opentelemetry.io/otel/trace"
)

func TestAPIScanErrorV8PreservesFamiliesDimensionsAndCorrelation(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	api := &APIServer{}
	api.bindObservabilityV8Runtimes(runtime, nil, nil, runtime)
	ctx, spanContext := platformHealthCorrelatedContext(t)
	ctx = audit.ContextWithEnvelope(ctx, audit.CorrelationEnvelope{
		RunID: "run-scan", RequestID: "request-scan", SessionID: "session-scan",
		TurnID: "turn-scan", AgentID: "agent-scan", Connector: "codex",
	})
	ctx = trace.ContextWithSpanContext(ctx, spanContext)

	tests := []struct {
		scanner string
		target  string
		reason  string
	}{
		{scanner: "skill-scanner", target: "skill", reason: "timeout"},
		{scanner: "plugin-scanner", target: "plugin", reason: "parse"},
		{scanner: "mcp-scanner", target: "mcp", reason: "crash"},
		{scanner: "codeguard", target: "code", reason: "not_found"},
	}
	for _, test := range tests {
		api.recordAPIScanErrorV8(ctx, test.scanner, test.target, test.reason)
	}

	metrics := generatedMetricByName(
		capture.metricSnapshot(), observability.TelemetryInstrumentDefenseClawScanErrors,
	)
	if len(metrics) != len(tests) {
		t.Fatalf("generated scan error metrics=%d want=%d", len(metrics), len(tests))
	}
	for index, metric := range metrics {
		test := tests[index]
		attributes := metric.Attributes()
		if metric.CanonicalRecord().Source() != observability.SourceScanner ||
			metric.CanonicalRecord().Connector() != "codex" ||
			attributes["defenseclaw.scan.scanner"] != test.scanner ||
			attributes["defenseclaw.metric.target_type"] != test.target ||
			attributes["defenseclaw.metric.error_type"] != test.reason {
			t.Fatalf("scan error %d record=%s/%q attributes=%v", index,
				metric.CanonicalRecord().Source(), metric.CanonicalRecord().Connector(), attributes)
		}
		correlation := metric.CanonicalRecord().Correlation()
		if correlation.TraceID != spanContext.TraceID().String() ||
			correlation.SpanID != spanContext.SpanID().String() ||
			correlation.RequestID != "request-scan" || correlation.SessionID != "session-scan" ||
			correlation.TurnID != "turn-scan" || correlation.AgentID != "agent-scan" {
			t.Fatalf("scan error %d correlation=%+v", index, correlation)
		}
	}
}

func TestClassifyScanErrorRecognizesFilesystemAbsence(t *testing.T) {
	if got := classifyScanError(fmt.Errorf("wrapped scanner failure: %w", os.ErrNotExist)); got != "not_found" {
		t.Fatalf("wrapped filesystem absence classified as %q", got)
	}
	for _, message := range []string{
		"open /missing/file: no such file or directory",
		`CreateFile C:\missing\file: The system cannot find the file specified.`,
		`CreateFile C:\missing\dir\file: The system cannot find the path specified.`,
	} {
		if got := classifyScanError(&scanErrorText{message}); got != "not_found" {
			t.Fatalf("filesystem absence %q classified as %q", message, got)
		}
	}
}

type scanErrorText struct{ text string }

func (err *scanErrorText) Error() string { return err.text }
