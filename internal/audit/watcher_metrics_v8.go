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

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"
)

type watcherMetricV8Kind uint8

const (
	watcherMetricV8Invalid watcherMetricV8Kind = iota
	watcherMetricV8Event
	watcherMetricV8Error
	watcherMetricV8AdmissionDecision
	watcherMetricV8ScanError
	watcherMetricV8QuarantineAction
	watcherMetricV8BlockSLO
	watcherMetricV8ProvenanceBump
)

type watcherMetricV8Input struct {
	kind watcherMetricV8Kind

	eventType, targetType, connector string
	decision, source                 string
	scanner, errorType               string
	quarantineOp, quarantineResult   string
	reason                           string
	latencyMS                        float64
}

// RecordWatcherEventMetric records one filesystem/rescan watcher event through
// the generated v8 runtime. Empty connector identities retain the established
// local-observability "unknown" label instead of creating a missing series.
func (l *Logger) RecordWatcherEventMetric(
	ctx context.Context,
	eventType, targetType, connector string,
) error {
	return l.recordWatcherMetricV8(ctx, watcherMetricV8Input{
		kind: watcherMetricV8Event, eventType: eventType,
		targetType: targetType, connector: connector,
	})
}

// RecordWatcherErrorMetric records one filesystem watcher error.
func (l *Logger) RecordWatcherErrorMetric(ctx context.Context) error {
	return l.recordWatcherMetricV8(ctx, watcherMetricV8Input{kind: watcherMetricV8Error})
}

// RecordAdmissionDecisionMetric records the final watcher admission decision.
func (l *Logger) RecordAdmissionDecisionMetric(
	ctx context.Context,
	decision, targetType, source string,
) error {
	return l.recordWatcherMetricV8(ctx, watcherMetricV8Input{
		kind: watcherMetricV8AdmissionDecision, decision: decision,
		targetType: targetType, source: source,
	})
}

// RecordWatcherScanErrorMetric records a failed scanner invocation in the
// asset.scan bucket without invoking the legacy telemetry.Provider.
func (l *Logger) RecordWatcherScanErrorMetric(
	ctx context.Context,
	scanner, targetType, errorType string,
) error {
	return l.recordWatcherMetricV8(ctx, watcherMetricV8Input{
		kind: watcherMetricV8ScanError, scanner: scanner,
		targetType: targetType, errorType: errorType,
	})
}

// RecordQuarantineActionMetric records a filesystem quarantine outcome. The
// successful watcher path is already emitted atomically with
// LogEnforcementQuarantineApplied; this entry point covers failure outcomes.
func (l *Logger) RecordQuarantineActionMetric(
	ctx context.Context,
	op, result string,
) error {
	return l.recordWatcherMetricV8(ctx, watcherMetricV8Input{
		kind:         watcherMetricV8QuarantineAction,
		quarantineOp: op, quarantineResult: result,
	})
}

// RecordBlockSLOMetric records watcher admission latency using the established
// defenseclaw.slo.block.latency instrument and target_type dashboard label.
func (l *Logger) RecordBlockSLOMetric(
	ctx context.Context,
	targetType string,
	latencyMS float64,
) error {
	return l.recordWatcherMetricV8(ctx, watcherMetricV8Input{
		kind: watcherMetricV8BlockSLO, targetType: targetType, latencyMS: latencyMS,
	})
}

// RecordProvenanceBumpMetric records a watcher-driven provenance generation
// bump through the generated diagnostic metric family.
func (l *Logger) RecordProvenanceBumpMetric(ctx context.Context, reason string) error {
	return l.recordWatcherMetricV8(ctx, watcherMetricV8Input{
		kind: watcherMetricV8ProvenanceBump, reason: reason,
	})
}

func (l *Logger) recordWatcherMetricV8(ctx context.Context, input watcherMetricV8Input) error {
	binding := l.runtimeV8BindingSnapshot()
	if binding.metricBatch == nil {
		return fmt.Errorf("audit: watcher v8 metric runtime is unavailable")
	}
	metric, err := newWatcherRuntimeV8GeneratedMetric(ctx, input)
	if err != nil {
		return err
	}
	return l.recordRuntimeV8GeneratedMetricBatch(ctx, binding, []RuntimeV8GeneratedMetric{metric})
}

func newWatcherRuntimeV8GeneratedMetric(
	ctx context.Context,
	input watcherMetricV8Input,
) (RuntimeV8GeneratedMetric, error) {
	family := watcherMetricV8Family(input.kind)
	if family == "" || input.latencyMS < 0 || math.IsNaN(input.latencyMS) || math.IsInf(input.latencyMS, 0) {
		return RuntimeV8GeneratedMetric{}, fmt.Errorf("audit: invalid generated watcher metric input")
	}
	event := newWatcherMetricV8Event(ctx)
	if event.Connector == "" && observability.IsStableToken(strings.TrimSpace(input.connector)) {
		event.Connector = strings.TrimSpace(input.connector)
	}
	return RuntimeV8GeneratedMetric{
		family: family,
		build: func(snapshot RuntimeV8BuildContext) (observability.Record, error) {
			return buildWatcherRuntimeV8GeneratedMetric(snapshot, event, input)
		},
	}, nil
}

func watcherMetricV8Family(kind watcherMetricV8Kind) observability.EventName {
	switch kind {
	case watcherMetricV8Event:
		return observability.EventName(observability.TelemetryInstrumentDefenseClawWatcherEvents)
	case watcherMetricV8Error:
		return observability.EventName(observability.TelemetryInstrumentDefenseClawWatcherErrors)
	case watcherMetricV8AdmissionDecision:
		return observability.EventName(observability.TelemetryInstrumentDefenseClawAdmissionDecisions)
	case watcherMetricV8ScanError:
		return observability.EventName(observability.TelemetryInstrumentDefenseClawScanErrors)
	case watcherMetricV8QuarantineAction:
		return observability.EventName(observability.TelemetryInstrumentDefenseClawQuarantineActions)
	case watcherMetricV8BlockSLO:
		return observability.EventName(observability.TelemetryInstrumentDefenseClawSloBlockLatency)
	case watcherMetricV8ProvenanceBump:
		return observability.EventName(observability.TelemetryInstrumentDefenseClawProvenanceBumps)
	default:
		return ""
	}
}

func newWatcherMetricV8Event(ctx context.Context) Event {
	if ctx == nil {
		ctx = context.Background()
	}
	event := Event{
		Timestamp: time.Now().UTC(), Action: string(ActionSidecarWatcherVerdict),
		Actor: "watcher", Severity: "INFO",
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

func buildWatcherRuntimeV8GeneratedMetric(
	snapshot RuntimeV8BuildContext,
	event Event,
	input watcherMetricV8Input,
) (observability.Record, error) {
	if snapshot.ConfigGeneration > math.MaxInt64 || !observability.IsStableToken(snapshot.ConfigDigest) {
		return observability.Record{}, fmt.Errorf("audit: invalid v8 watcher metric build context")
	}
	builder, err := observability.NewFamilyBuilder(
		observability.ClockFunc(func() time.Time { return event.Timestamp.UTC() }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) { return uuid.NewString(), nil }),
	)
	if err != nil {
		return observability.Record{}, err
	}
	connector := strings.TrimSpace(input.connector)
	if !observability.IsStableToken(connector) {
		connector = "unknown"
	}
	envelope := observability.FamilyEnvelopeInput{
		ObservedAt:  observability.Present(event.Timestamp.UTC()),
		Source:      observability.SourceWatcher,
		Connector:   event.Connector,
		Action:      event.Action,
		Phase:       "metrics",
		Correlation: controlPlaneV8Correlation(event),
		Provenance: observability.FamilyProvenanceInput{
			Producer: "watcher", BinaryVersion: event.BinaryVersion,
			ConfigGeneration: int64(snapshot.ConfigGeneration), ConfigDigest: snapshot.ConfigDigest,
		},
	}
	optional := optionalAuditMetricDimension
	switch input.kind {
	case watcherMetricV8Event:
		return builder.BuildMetricDefenseClawWatcherEvents(observability.MetricDefenseClawWatcherEventsInput{
			Envelope: envelope, Value: 1,
			DefenseClawConnectorSource:  observability.Present(connector),
			DefenseClawMetricEventType:  optional(input.eventType),
			DefenseClawMetricTargetType: optional(input.targetType),
		})
	case watcherMetricV8Error:
		return builder.BuildMetricDefenseClawWatcherErrors(observability.MetricDefenseClawWatcherErrorsInput{
			Envelope: envelope, Value: 1,
		})
	case watcherMetricV8AdmissionDecision:
		return builder.BuildMetricDefenseClawAdmissionDecisions(observability.MetricDefenseClawAdmissionDecisionsInput{
			Envelope: envelope, Value: 1,
			DefenseClawMetricDecision:   optional(input.decision),
			DefenseClawMetricSource:     optional(input.source),
			DefenseClawMetricTargetType: optional(input.targetType),
		})
	case watcherMetricV8ScanError:
		return builder.BuildMetricDefenseClawScanErrors(observability.MetricDefenseClawScanErrorsInput{
			Envelope: envelope, Value: 1,
			DefenseClawMetricErrorType:  optional(input.errorType),
			DefenseClawScanScanner:      optionalScanV8Identifier(input.scanner),
			DefenseClawMetricTargetType: optional(input.targetType),
		})
	case watcherMetricV8QuarantineAction:
		return builder.BuildMetricDefenseClawQuarantineActions(observability.MetricDefenseClawQuarantineActionsInput{
			Envelope: envelope, Value: 1,
			DefenseClawMetricQuarantineOp:     optional(input.quarantineOp),
			DefenseClawMetricQuarantineResult: optional(input.quarantineResult),
		})
	case watcherMetricV8BlockSLO:
		return builder.BuildMetricDefenseClawSloBlockLatency(observability.MetricDefenseClawSloBlockLatencyInput{
			Envelope: envelope, Value: input.latencyMS,
			DefenseClawMetricTargetType: optional(input.targetType),
		})
	case watcherMetricV8ProvenanceBump:
		return builder.BuildMetricDefenseClawProvenanceBumps(observability.MetricDefenseClawProvenanceBumpsInput{
			Envelope: envelope, Value: 1,
			DefenseClawMetricReason: optional(input.reason),
		})
	default:
		return observability.Record{}, fmt.Errorf("audit: unsupported generated watcher metric family")
	}
}
