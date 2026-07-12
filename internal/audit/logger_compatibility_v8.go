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
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	"github.com/google/uuid"
)

// compatibilityAuditV8Options selects only facts already authorized by the
// generated producer registry. It is used after every richer typed adapter has
// declined an action, so compatibility identities cannot replace a canonical
// family that has source-backed fields available.
type compatibilityAuditV8Options struct {
	classification   observability.ClassificationContext
	source           observability.Source
	phase            string
	outcome          observability.Outcome
	companionMetrics []RuntimeV8GeneratedMetric
}

// emitCompatibilityAuditV8 is the terminal v8 owner for registered audit
// actions that still have a compatibility-only family. Once v8 has ever been
// bound, an unavailable runtime is an error and never reopens the legacy
// Provider/sink/structured fanout path.
func (l *Logger) emitCompatibilityAuditV8(
	ctx context.Context,
	event Event,
	options compatibilityAuditV8Options,
) (auditV8Disposition, error) {
	binding := l.runtimeV8BindingSnapshot()
	if binding.emitter == nil {
		return auditV8Persisted, fmt.Errorf("audit: v8 compatibility runtime is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	classification := options.classification
	classification.RawSeverity = event.Severity
	registered, found := observability.AuditActionClassification(observability.ProducerKey(event.Action))
	if !found {
		return auditV8Persisted, fmt.Errorf("audit: action %q has no registered v8 classification", event.Action)
	}
	resolved, err := registered.Resolve(classification)
	if err != nil {
		return auditV8Persisted, fmt.Errorf("audit: classify v8 compatibility action %q: %w", event.Action, err)
	}
	source := options.source
	if source == "" {
		source = controlPlaneV8Source(event, controlPlaneV8FamilyNone)
	}
	phase := options.phase
	if phase == "" {
		phase = "persistence"
	}
	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerAuditAction,
		observability.ProducerKey(event.Action),
		classification,
		source,
		event.Connector,
		observability.ProducerKey(event.Action),
	)
	if err != nil {
		return auditV8Persisted, fmt.Errorf("audit: route v8 compatibility action %q: %w", event.Action, err)
	}
	result, err := binding.emitter.EmitRuntimeV8(
		contextWithLegacyEventProjection(ctx, event), metadata,
		func(snapshot RuntimeV8BuildContext, admission router.Admission) (observability.Record, error) {
			return buildCompatibilityAuditV8Record(
				event, classification, source, phase, options.outcome, snapshot, admission,
			)
		},
	)
	if err != nil {
		return auditV8Persisted, fmt.Errorf("audit: emit v8 compatibility action %q: %w", event.Action, err)
	}
	disposition, err := runtimeV8Disposition(result, resolved.Mandatory)
	if err != nil {
		return auditV8Persisted, fmt.Errorf("audit: v8 compatibility action %q: %w", event.Action, err)
	}
	if disposition == auditV8Persisted {
		metric, metricErr := newAuditEventRuntimeV8GeneratedMetric(event)
		if metricErr == nil {
			metrics := make([]RuntimeV8GeneratedMetric, 0, 1+len(options.companionMetrics))
			metrics = append(metrics, metric)
			metrics = append(metrics, options.companionMetrics...)
			_ = l.recordRuntimeV8GeneratedMetricBatch(ctx, binding, metrics)
		}
	}
	return disposition, nil
}

func buildCompatibilityAuditV8Record(
	event Event,
	classification observability.ClassificationContext,
	source observability.Source,
	phase string,
	outcome observability.Outcome,
	snapshot RuntimeV8BuildContext,
	admission router.Admission,
) (observability.Record, error) {
	if event.ID == "" || event.Timestamp.IsZero() || event.BinaryVersion == "" ||
		snapshot.ConfigGeneration > math.MaxInt64 || !observability.IsStableToken(snapshot.ConfigDigest) {
		return observability.Record{}, fmt.Errorf("audit: invalid v8 compatibility build context")
	}
	builder, err := observability.NewRecordBuilder(
		observability.ClockFunc(func() time.Time { return event.Timestamp.UTC() }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) { return event.ID, nil }),
	)
	if err != nil {
		return observability.Record{}, err
	}
	provenance := observability.Provenance{
		Producer:              "audit_logger",
		BinaryVersion:         event.BinaryVersion,
		RegistrySchemaVersion: observability.CurrentRecordSchemaVersion,
		ConfigGeneration:      int64(snapshot.ConfigGeneration),
		ConfigDigest:          snapshot.ConfigDigest,
	}
	if admission == router.AdmissionFloor {
		return builder.BuildMandatoryFloorLog(observability.MandatoryFloorLogInput{
			ProducerKind: observability.ProducerAuditAction, ProducerKey: observability.ProducerKey(event.Action),
			ClassificationContext: classification, ObservedAt: timePointer(event.Timestamp.UTC()),
			Source: source, Connector: event.Connector, Action: event.Action, Phase: phase,
			Outcome: optionsFloorOutcome(outcome), Correlation: controlPlaneV8Correlation(event),
			Provenance: provenance,
		})
	}
	if admission != router.AdmissionOrdinary {
		return observability.Record{}, fmt.Errorf("audit: v8 compatibility action has no admitted build path")
	}
	body, fieldClasses := compatibilityAuditV8Body(event)
	record, err := builder.BuildClassifiedLog(observability.ClassifiedLogInput{
		ProducerKind: observability.ProducerAuditAction, ProducerKey: observability.ProducerKey(event.Action),
		ClassificationContext: classification, ObservedAt: timePointer(event.Timestamp.UTC()),
		Source: source, Connector: event.Connector, Action: event.Action, Phase: phase,
		Outcome: outcome, Correlation: controlPlaneV8Correlation(event), Provenance: provenance,
		Body: body, FieldClasses: fieldClasses,
	})
	if err != nil {
		return observability.Record{}, err
	}
	if record.RecordID() != event.ID || !record.Timestamp().Equal(event.Timestamp.UTC()) || record.IsFloorOnly() {
		return observability.Record{}, fmt.Errorf("audit: v8 compatibility record violated its identity contract")
	}
	return record, nil
}

func optionsFloorOutcome(outcome observability.Outcome) observability.Outcome {
	// Mandatory compatibility records are always terminal facts. A caller with
	// no more specific source-backed outcome uses completed rather than an empty
	// floor value so the floor remains operationally useful.
	if outcome == "" {
		return observability.OutcomeCompleted
	}
	return outcome
}

func compatibilityAuditV8Body(event Event) (map[string]any, map[string]observability.FieldClass) {
	body := map[string]any{
		"actor":   event.Actor,
		"details": event.Details,
		"target":  event.Target,
	}
	classes := map[string]observability.FieldClass{
		"/actor":   observability.FieldClassIdentifier,
		"/details": observability.FieldClassContent,
		"/target":  observability.FieldClassContent,
	}
	if len(event.Structured) > 0 {
		if encoded, err := json.Marshal(event.Structured); err == nil {
			body["structured_json"] = string(encoded)
			classes["/structured_json"] = observability.FieldClassContent
		}
	}
	return body, classes
}

func (l *Logger) emitRuntimeAlertV8(
	ctx context.Context,
	event Event,
	source string,
	errorCode observability.Optional[string],
) (auditV8Disposition, error) {
	binding := l.runtimeV8BindingSnapshot()
	if binding.emitter == nil {
		return auditV8Persisted, fmt.Errorf("audit: v8 runtime-alert runtime is unavailable")
	}
	safeSource := safeSinkHealthDimension(source)
	disposition, err := l.emitPlatformHealthV8Occurrence(ctx, binding, sinkHealthV8Occurrence{
		family: sinkHealthV8Degraded, action: ActionAlert, phase: "alert",
		outcome: observability.OutcomeFailed, severity: event.Severity,
		subsystem: safeSource, healthState: "degraded", errorCode: errorCode,
		event: event, timestamp: event.Timestamp,
	})
	if err != nil {
		return auditV8Persisted, err
	}
	if metric, metricErr := newRuntimeAlertV8GeneratedMetric(event, safeSource); metricErr == nil {
		_ = l.recordRuntimeV8GeneratedMetricBatch(ctx, binding, []RuntimeV8GeneratedMetric{metric})
	}
	return disposition, nil
}

func runtimeAlertErrorCode(details string) observability.Optional[string] {
	var payload struct {
		Summary string `json:"summary"`
	}
	if err := json.Unmarshal([]byte(details), &payload); err != nil ||
		!observability.IsStableToken(payload.Summary) {
		return observability.Absent[string]()
	}
	return observability.Present(payload.Summary)
}

func newRuntimeAlertV8GeneratedMetric(event Event, source string) (RuntimeV8GeneratedMetric, error) {
	normalized := observability.NormalizeSeverity(event.Severity)
	if event.Timestamp.IsZero() || !normalized.Valid || !normalized.Present ||
		!observability.IsStableToken(source) {
		return RuntimeV8GeneratedMetric{}, fmt.Errorf("audit: invalid generated runtime-alert metric input")
	}
	connector := strings.TrimSpace(event.Connector)
	if !observability.IsStableToken(connector) {
		connector = "unknown"
	}
	return RuntimeV8GeneratedMetric{
		family: observability.EventName(observability.TelemetryInstrumentDefenseClawAlertCount),
		build: func(snapshot RuntimeV8BuildContext) (observability.Record, error) {
			if snapshot.ConfigGeneration > math.MaxInt64 || !observability.IsStableToken(snapshot.ConfigDigest) {
				return observability.Record{}, fmt.Errorf("audit: invalid v8 runtime-alert metric build context")
			}
			builder, err := observability.NewFamilyBuilder(
				observability.ClockFunc(func() time.Time { return event.Timestamp.UTC() }),
				observability.OccurrenceIDGeneratorFunc(func() (string, error) { return uuid.NewString(), nil }),
			)
			if err != nil {
				return observability.Record{}, err
			}
			return builder.BuildMetricDefenseClawAlertCount(observability.MetricDefenseClawAlertCountInput{
				Envelope: observability.FamilyEnvelopeInput{
					ObservedAt: observability.Present(event.Timestamp.UTC()), Source: observability.SourceSystem,
					Connector: event.Connector, Action: event.Action, Phase: "alert",
					Correlation: controlPlaneV8Correlation(event),
					Provenance: observability.FamilyProvenanceInput{
						Producer: "audit_logger", BinaryVersion: event.BinaryVersion,
						ConfigGeneration: int64(snapshot.ConfigGeneration), ConfigDigest: snapshot.ConfigDigest,
					},
				},
				Value: 1, DefenseClawMetricAlertSeverity: observability.Present(string(normalized.Severity)),
				DefenseClawMetricAlertSource: observability.Present(source),
				DefenseClawMetricAlertType:   observability.Present("runtime"),
				DefenseClawConnectorSource:   observability.Present(connector),
			})
		},
	}, nil
}
