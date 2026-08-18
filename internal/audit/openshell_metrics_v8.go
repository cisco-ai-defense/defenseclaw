// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/version"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"
)

// RecordOpenShellExitMetric records a sandbox subprocess exit through the
// generated v8 metric family. OpenShell never receives the legacy telemetry
// provider; this audit-owned operation keeps routing, export, and generation
// coherence inside the canonical runtime.
func (l *Logger) RecordOpenShellExitMetric(
	ctx context.Context,
	command string,
	exitCode int,
) error {
	command = strings.TrimSpace(command)
	if command == "" || len(command) > 256 || !utf8.ValidString(command) ||
		int64(exitCode) < math.MinInt32 || int64(exitCode) > math.MaxInt32 {
		return fmt.Errorf("audit: invalid OpenShell exit metric input")
	}
	binding := l.runtimeV8BindingSnapshot()
	if binding.metricBatch == nil {
		return fmt.Errorf("audit: OpenShell v8 metric runtime is unavailable")
	}
	event := newOpenShellMetricV8Event(ctx)
	metric := RuntimeV8GeneratedMetric{
		family: observability.EventName(observability.TelemetryInstrumentDefenseClawOpenshellExit),
		build: func(snapshot RuntimeV8BuildContext) (observability.Record, error) {
			return buildOpenShellExitMetricV8(snapshot, event, command, int64(exitCode))
		},
	}
	return l.recordRuntimeV8GeneratedMetricBatch(ctx, binding, []RuntimeV8GeneratedMetric{metric})
}

func newOpenShellMetricV8Event(ctx context.Context) Event {
	if ctx == nil {
		ctx = context.Background()
	}
	event := Event{
		Timestamp: time.Now().UTC(), Action: string(ActionToolResult),
		Actor: "openshell", Severity: "HIGH",
	}
	applyEnvelope(&event, EnvelopeFromContext(ctx))
	spanContext := trace.SpanContextFromContext(ctx)
	if spanContext.IsValid() {
		if event.TraceID == "" {
			event.TraceID = spanContext.TraceID().String()
			event.SpanID = spanContext.SpanID().String()
		}
		if event.TraceID == spanContext.TraceID().String() && event.SpanID == "" {
			event.SpanID = spanContext.SpanID().String()
		}
	}
	stampAuditEventEnvelope(&event)
	return event
}

func buildOpenShellExitMetricV8(
	snapshot RuntimeV8BuildContext,
	event Event,
	command string,
	exitCode int64,
) (observability.Record, error) {
	if snapshot.ConfigGeneration > math.MaxInt64 ||
		!observability.IsStableToken(snapshot.ConfigDigest) || event.Timestamp.IsZero() {
		return observability.Record{}, fmt.Errorf("audit: invalid OpenShell v8 metric build context")
	}
	builder, err := observability.NewFamilyBuilder(
		observability.ClockFunc(func() time.Time { return event.Timestamp.UTC() }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) { return uuid.NewString(), nil }),
	)
	if err != nil {
		return observability.Record{}, err
	}
	return builder.BuildMetricDefenseClawOpenshellExit(
		observability.MetricDefenseClawOpenshellExitInput{
			Envelope: observability.FamilyEnvelopeInput{
				ObservedAt: observability.Present(event.Timestamp.UTC()),
				Source:     observability.SourceSystem, Action: event.Action, Phase: "execution",
				Correlation: controlPlaneV8Correlation(event),
				Provenance: observability.FamilyProvenanceInput{
					Producer: "openshell", BinaryVersion: version.Current().BinaryVersion,
					ConfigGeneration: int64(snapshot.ConfigGeneration), ConfigDigest: snapshot.ConfigDigest,
				},
			},
			Value:                    1,
			DefenseClawMetricCommand: observability.Present(command),
			DefenseClawToolExitCode:  observability.Present(exitCode),
		},
	)
}
