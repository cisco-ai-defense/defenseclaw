// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const otelTracerName = "github.com/defenseclaw/defenseclaw/internal/scanner"

// BeginScanSpan starts the "scanner.scan" span. End with FinishScanSpan.
func BeginScanSpan(ctx context.Context, scannerName, target, targetType string, agent AgentIdentity) (context.Context, trace.Span) {
	tr := otel.Tracer(otelTracerName)
	attrs := []trace.SpanStartOption{
		trace.WithAttributes(
			attribute.String("scanner", scannerName),
			attribute.String("target", target),
			attribute.String("target_type", targetType),
			attribute.String("agent.id", agent.AgentID),
			attribute.String("agent.name", agent.AgentName),
			attribute.String("agent.instance_id", agent.AgentInstanceID),
			attribute.String("sidecar.instance_id", agent.SidecarInstanceID),
		),
	}
	return tr.Start(ctx, "scanner.scan", attrs...)
}

// FinishScanSpan completes the span with scan outcome attributes.
func FinishScanSpan(sp trace.Span, result *ScanResult, exitCode int, err error) {
	if sp == nil {
		return
	}
	defer sp.End()
	if result != nil {
		sp.SetAttributes(
			attribute.Int64("duration_ms", result.Duration.Milliseconds()),
			attribute.Int("finding_count", len(result.Findings)),
			attribute.String("verdict", VerdictForResult(result)),
			attribute.Int("exit_code", exitCode),
		)
	} else {
		sp.SetAttributes(attribute.Int("exit_code", exitCode))
	}
	if err != nil {
		sp.RecordError(err)
		sp.SetStatus(codes.Error, err.Error())
		return
	}
	sp.SetStatus(codes.Ok, "")
}
