// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/version"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"
)

// RecordSQLiteBusyMetric records one retryable SQLite contention observation
// through the generated v8 family. Store retry behavior is independent of
// collection or export: an unavailable runtime drops only this diagnostic.
func (l *Logger) RecordSQLiteBusyMetric(ctx context.Context, operation string) error {
	operationValue := optionalAuditMetricDimension(operation)
	if !operationValue.IsPresent() {
		return fmt.Errorf("audit: invalid SQLite busy metric operation")
	}
	binding := l.runtimeV8BindingSnapshot()
	if binding.metricBatch == nil {
		return fmt.Errorf("audit: SQLite busy v8 metric runtime is unavailable")
	}
	event := newSQLiteBusyMetricV8Event(ctx)
	metric := RuntimeV8GeneratedMetric{
		family: observability.EventName(observability.TelemetryInstrumentDefenseClawSqliteBusyRetries),
		build: func(snapshot RuntimeV8BuildContext) (observability.Record, error) {
			if snapshot.ConfigGeneration > math.MaxInt64 ||
				!observability.IsStableToken(snapshot.ConfigDigest) {
				return observability.Record{}, fmt.Errorf("audit: invalid SQLite busy v8 build context")
			}
			builder, err := observability.NewFamilyBuilder(
				observability.ClockFunc(func() time.Time { return event.Timestamp.UTC() }),
				observability.OccurrenceIDGeneratorFunc(func() (string, error) { return uuid.NewString(), nil }),
			)
			if err != nil {
				return observability.Record{}, err
			}
			return builder.BuildMetricDefenseClawSqliteBusyRetries(
				observability.MetricDefenseClawSqliteBusyRetriesInput{
					Envelope: observability.FamilyEnvelopeInput{
						ObservedAt: observability.Present(event.Timestamp.UTC()),
						Source:     observability.SourceSystem, Action: event.Action, Phase: "retry",
						Correlation: controlPlaneV8Correlation(event),
						Provenance: observability.FamilyProvenanceInput{
							Producer: "sqlite", BinaryVersion: version.Current().BinaryVersion,
							ConfigGeneration: int64(snapshot.ConfigGeneration), ConfigDigest: snapshot.ConfigDigest,
						},
					},
					Value: 1, DefenseClawMetricOperation: operationValue,
				},
			)
		},
	}
	return l.recordRuntimeV8GeneratedMetricBatch(ctx, binding, []RuntimeV8GeneratedMetric{metric})
}

// RecordSchemaViolationMetric is the gatewaylog validator callback. The
// validator remains independent of telemetry success, so this best-effort
// wrapper intentionally has no return value.
func (l *Logger) RecordSchemaViolationMetric(
	eventType gatewaylog.EventType,
	code string,
	_ string,
) {
	_ = l.recordSchemaViolationMetricV8(context.Background(), string(eventType), code)
}

func (l *Logger) recordSchemaViolationMetricV8(ctx context.Context, eventType, code string) error {
	eventTypeValue := optionalAuditMetricDimension(eventType)
	codeValue := optionalAuditMetricDimension(code)
	if !eventTypeValue.IsPresent() || !codeValue.IsPresent() {
		return fmt.Errorf("audit: invalid schema violation metric input")
	}
	binding := l.runtimeV8BindingSnapshot()
	if binding.metricBatch == nil {
		return fmt.Errorf("audit: schema violation v8 metric runtime is unavailable")
	}
	event := newSQLiteBusyMetricV8Event(ctx)
	event.Action = "schema-violation"
	metric := RuntimeV8GeneratedMetric{
		family: observability.EventName(observability.TelemetryInstrumentDefenseClawSchemaViolations),
		build: func(snapshot RuntimeV8BuildContext) (observability.Record, error) {
			if snapshot.ConfigGeneration > math.MaxInt64 ||
				!observability.IsStableToken(snapshot.ConfigDigest) {
				return observability.Record{}, fmt.Errorf("audit: invalid schema violation v8 build context")
			}
			builder, err := observability.NewFamilyBuilder(
				observability.ClockFunc(func() time.Time { return event.Timestamp.UTC() }),
				observability.OccurrenceIDGeneratorFunc(func() (string, error) { return uuid.NewString(), nil }),
			)
			if err != nil {
				return observability.Record{}, err
			}
			return builder.BuildMetricDefenseClawSchemaViolations(
				observability.MetricDefenseClawSchemaViolationsInput{
					Envelope: observability.FamilyEnvelopeInput{
						ObservedAt: observability.Present(event.Timestamp.UTC()),
						Source:     observability.SourceSystem, Action: event.Action, Phase: "validation",
						Correlation: controlPlaneV8Correlation(event),
						Provenance: observability.FamilyProvenanceInput{
							Producer: "gatewaylog", BinaryVersion: version.Current().BinaryVersion,
							ConfigGeneration: int64(snapshot.ConfigGeneration), ConfigDigest: snapshot.ConfigDigest,
						},
					},
					Value: 1, DefenseClawMetricEventType: eventTypeValue,
					DefenseClawMetricCode: codeValue,
				},
			)
		},
	}
	return l.recordRuntimeV8GeneratedMetricBatch(ctx, binding, []RuntimeV8GeneratedMetric{metric})
}

func newSQLiteBusyMetricV8Event(ctx context.Context) Event {
	if ctx == nil {
		ctx = context.Background()
	}
	event := Event{
		Timestamp: time.Now().UTC(), Action: string(ActionSinkFailure),
		Actor: "sqlite", Severity: "LOW",
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
