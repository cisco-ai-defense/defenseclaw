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
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	"github.com/defenseclaw/defenseclaw/internal/version"
	"github.com/google/uuid"
)

// RuntimeV8GeneratedMetric is an opaque, audit-owned generated metric
// operation. Its fields are private so callers cannot substitute a handwritten
// family identity or builder. The runtime adapter still validates the returned
// record against the generated registry before recording it.
type RuntimeV8GeneratedMetric struct {
	family observability.EventName
	build  RuntimeV8MetricBuilder
}

// RuntimeV8MetricBuilder receives only the immutable generation/digest pair.
// It cannot access the runtime graph or telemetry provider.
type RuntimeV8MetricBuilder func(RuntimeV8BuildContext) (observability.Record, error)

// Family exposes the exact generated identity to the cycle-breaking runtime
// adapter. A zero value is invalid and is rejected by Build.
func (metric RuntimeV8GeneratedMetric) Family() observability.EventName { return metric.family }

// Build invokes the sealed generated-family callback.
func (metric RuntimeV8GeneratedMetric) Build(
	snapshot RuntimeV8BuildContext,
) (observability.Record, error) {
	if metric.family == "" || metric.build == nil {
		return observability.Record{}, fmt.Errorf("audit: generated metric operation is unavailable")
	}
	record, err := metric.build(snapshot)
	if err != nil {
		return observability.Record{}, err
	}
	if record.Signal() != observability.SignalMetrics || record.EventName() != metric.family {
		return observability.Record{}, fmt.Errorf("audit: generated metric identity mismatch")
	}
	return record, nil
}

// RuntimeV8MetricEmitter is the narrow optional metric capability implemented
// by the owned v8 runtime. It accepts only the opaque generated operation above;
// audit producers never receive a graph, provider, meter, or free-form metric
// recording API.
type RuntimeV8MetricEmitter interface {
	RecordRuntimeV8GeneratedMetric(context.Context, RuntimeV8GeneratedMetric) error
}

// RuntimeV8MetricBatchEmitter records a bounded set of related generated
// metrics on one immutable runtime generation. The batch is intentionally
// expressed in audit-owned opaque operations so this package cannot select an
// arbitrary family at the runtime boundary.
type RuntimeV8MetricBatchEmitter interface {
	RecordRuntimeV8GeneratedMetricBatch(context.Context, []RuntimeV8GeneratedMetric) error
}

type sinkHealthV8Family uint8

const (
	sinkHealthV8Invalid sinkHealthV8Family = iota
	sinkHealthV8AuthenticationFailed
	sinkHealthV8AuthorizationDenied
	sinkHealthV8ExportFailed
	sinkHealthV8QueueFull
	sinkHealthV8Degraded
	sinkHealthV8Lifecycle
	sinkHealthV8Ready
	sinkHealthV8Restored
)

type sinkHealthV8Occurrence struct {
	family                       sinkHealthV8Family
	action                       Action
	phase                        string
	outcome                      observability.Outcome
	severity                     string
	subsystem                    string
	healthState                  string
	errorSummary                 observability.Optional[string]
	errorCode                    observability.Optional[string]
	durableHealthTransition      bool
	protectedBoundaryAuthFailure bool
	timestamp                    time.Time
	event                        Event
}

func (occurrence sinkHealthV8Occurrence) mandatory() bool {
	return occurrence.durableHealthTransition || occurrence.protectedBoundaryAuthFailure
}

func (occurrence sinkHealthV8Occurrence) eventName() observability.EventName {
	switch occurrence.family {
	case sinkHealthV8AuthenticationFailed:
		return observability.EventName(observability.TelemetryEventDestinationAuthenticationFailed)
	case sinkHealthV8AuthorizationDenied:
		return observability.EventName(observability.TelemetryEventDestinationAuthorizationDenied)
	case sinkHealthV8ExportFailed:
		return observability.EventName(observability.TelemetryEventDestinationExportFailed)
	case sinkHealthV8QueueFull:
		return observability.EventName(observability.TelemetryEventDestinationQueueFull)
	case sinkHealthV8Degraded:
		return observability.EventName(observability.TelemetryEventSubsystemDegraded)
	case sinkHealthV8Lifecycle:
		return observability.EventName(observability.TelemetryEventSubsystemLifecycle)
	case sinkHealthV8Ready:
		return observability.EventName(observability.TelemetryEventSubsystemReady)
	case sinkHealthV8Restored:
		return observability.EventName(observability.TelemetryEventSubsystemRestored)
	default:
		return ""
	}
}

// emitSinkHealthV8 emits exactly one generated platform-health log through the
// binding captured at the beginning of the sink occurrence. authoritative=true
// always suppresses legacy fallback, including a detached/unavailable runtime.
func (l *Logger) emitSinkHealthV8(
	ctx context.Context,
	binding runtimeV8Binding,
	occurrence sinkHealthV8Occurrence,
) error {
	_, err := l.emitPlatformHealthV8Occurrence(ctx, binding, occurrence)
	return err
}

func (l *Logger) emitPlatformHealthV8Occurrence(
	ctx context.Context,
	binding runtimeV8Binding,
	occurrence sinkHealthV8Occurrence,
) (auditV8Disposition, error) {
	if binding.emitter == nil {
		return auditV8Persisted, fmt.Errorf("audit: v8 platform health runtime is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if occurrence.timestamp.IsZero() {
		occurrence.timestamp = time.Now().UTC()
	}
	eventName := occurrence.eventName()
	if eventName == "" || !observability.IsStableToken(occurrence.phase) ||
		!observability.IsStableToken(occurrence.subsystem) {
		return auditV8Persisted, fmt.Errorf("audit: v8 platform health occurrence is invalid")
	}
	event := occurrence.event
	if event.Timestamp.IsZero() {
		event.Timestamp = occurrence.timestamp.UTC()
	}
	event.Action = string(occurrence.action)
	if event.Target == "" {
		event.Target = occurrence.subsystem
	}
	if event.Actor == "" {
		event.Actor = "defenseclaw"
	}
	event.Severity = occurrence.severity
	if event.RunID == "" {
		event.RunID = currentRunID()
	}
	if event.SidecarInstanceID == "" {
		event.SidecarInstanceID = ProcessAgentInstanceID()
	}
	if !occurrence.errorSummary.IsPresent() {
		occurrence.errorSummary = platformHealthErrorSummary(event.Details)
	}
	stampAuditEventEnvelope(&event)
	classification := observability.ClassificationContext{
		Bucket:      observability.BucketPlatformHealth,
		EventName:   eventName,
		RawSeverity: occurrence.severity,
		MandatoryFacts: observability.MandatoryFacts{
			DurableHealthTransition:      occurrence.durableHealthTransition,
			ProtectedBoundaryAuthFailure: occurrence.protectedBoundaryAuthFailure,
		},
	}
	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerAuditAction,
		observability.ProducerKey(occurrence.action),
		classification,
		observability.SourceSystem,
		event.Connector,
		observability.ProducerKey(occurrence.action),
	)
	if err != nil {
		return auditV8Persisted, fmt.Errorf("audit: classify v8 platform health: %w", err)
	}

	result, err := binding.emitter.EmitRuntimeV8(ctx, metadata, func(
		snapshot RuntimeV8BuildContext,
		admission router.Admission,
	) (observability.Record, error) {
		if admission == router.AdmissionFloor {
			return buildRuntimeV8FloorRecord(
				event, snapshot, classification, observability.SourceSystem,
				occurrence.phase, occurrence.outcome, controlPlaneV8Correlation(event),
			)
		}
		if admission != router.AdmissionOrdinary {
			return observability.Record{}, fmt.Errorf("audit: v8 sink health has no admitted build path")
		}
		builder, envelope, severity, logLevel, buildErr := runtimeV8FamilyBuildState(
			event, snapshot, observability.SourceSystem, occurrence.phase,
			controlPlaneV8Correlation(event),
		)
		if buildErr != nil {
			return observability.Record{}, buildErr
		}
		record, buildErr := buildSinkHealthV8Family(
			builder, envelope, severity, logLevel, occurrence,
		)
		return verifyRuntimeV8Record(record, buildErr, event, occurrence.mandatory())
	})
	if err != nil {
		return auditV8Persisted, fmt.Errorf("audit: emit v8 platform health: %w", err)
	}
	disposition, err := runtimeV8Disposition(result, occurrence.mandatory())
	if err != nil {
		return auditV8Persisted, err
	}
	if disposition == auditV8Persisted {
		// Preserve the durable health occurrence even if its independent
		// aggregate metric cannot be recorded. Returning an error here would
		// encourage callers to retry and duplicate the already-persisted log.
		_ = l.recordAuditEventMetricV8(ctx, binding, event)
	}
	return disposition, nil
}

func (l *Logger) emitAuditPlatformHealthV8(
	ctx context.Context,
	event Event,
) (auditV8Disposition, error) {
	occurrence, handled := auditPlatformHealthV8Occurrence(event)
	if !handled {
		return auditV8Unhandled, nil
	}
	binding := l.runtimeV8BindingSnapshot()
	return l.emitPlatformHealthV8Occurrence(ctx, binding, occurrence)
}

func auditPlatformHealthV8Occurrence(event Event) (sinkHealthV8Occurrence, bool) {
	occurrence := sinkHealthV8Occurrence{
		action: Action(event.Action), event: event, timestamp: event.Timestamp,
		errorSummary: platformHealthErrorSummary(event.Details),
	}
	switch Action(event.Action) {
	case ActionSidecarStart:
		occurrence.durableHealthTransition = true
		occurrence.family, occurrence.phase = sinkHealthV8Lifecycle, "startup"
		occurrence.outcome, occurrence.severity = observability.OutcomeAttempted, "INFO"
		occurrence.subsystem, occurrence.healthState = "sidecar", "starting"
	case ActionSidecarStop:
		occurrence.durableHealthTransition = true
		occurrence.family, occurrence.phase = sinkHealthV8Lifecycle, "shutdown"
		occurrence.outcome, occurrence.severity = observability.OutcomeCompleted, "INFO"
		occurrence.subsystem, occurrence.healthState = "sidecar", "stopped"
	case ActionGuardrailStart:
		occurrence.durableHealthTransition = true
		occurrence.family, occurrence.phase = sinkHealthV8Lifecycle, "startup"
		occurrence.outcome, occurrence.severity = observability.OutcomeAttempted, "INFO"
		occurrence.subsystem, occurrence.healthState = "guardrail", "starting"
	case ActionWatchStart:
		occurrence.durableHealthTransition = true
		occurrence.family, occurrence.phase = sinkHealthV8Lifecycle, "startup"
		occurrence.outcome, occurrence.severity = observability.OutcomeCompleted, "INFO"
		occurrence.subsystem, occurrence.healthState = "watcher", "ready"
	case ActionWatchStop:
		occurrence.durableHealthTransition = true
		occurrence.family, occurrence.phase = sinkHealthV8Lifecycle, "shutdown"
		occurrence.outcome, occurrence.severity = observability.OutcomeCompleted, "INFO"
		occurrence.subsystem, occurrence.healthState = "watcher", "stopped"
	case ActionSidecarConnected:
		occurrence.durableHealthTransition = true
		occurrence.family, occurrence.phase = sinkHealthV8Ready, "connection"
		occurrence.outcome, occurrence.severity = observability.OutcomeCompleted, "INFO"
		occurrence.subsystem, occurrence.healthState = "gateway", "ready"
	case ActionSidecarDisconnected:
		occurrence.durableHealthTransition = true
		occurrence.family, occurrence.phase = sinkHealthV8Degraded, "connection"
		occurrence.outcome, occurrence.severity = observability.OutcomeFailed, "HIGH"
		occurrence.subsystem, occurrence.healthState = "gateway", "degraded"
		occurrence.errorCode = observability.Present("connection_lost")
	case ActionGuardrailHealthy:
		occurrence.durableHealthTransition = true
		occurrence.family, occurrence.phase = sinkHealthV8Ready, "readiness"
		occurrence.outcome, occurrence.severity = observability.OutcomeCompleted, "INFO"
		occurrence.subsystem, occurrence.healthState = "guardrail", "ready"
	case ActionGuardrailDegraded:
		occurrence.durableHealthTransition = true
		occurrence.family, occurrence.phase = sinkHealthV8Degraded, "health"
		occurrence.outcome, occurrence.severity = observability.OutcomeFailed, "HIGH"
		occurrence.subsystem, occurrence.healthState = "guardrail", "degraded"
		occurrence.errorCode = observability.Present("guardrail_degraded")
	case ActionGatewayJudgeBodiesReady:
		occurrence.durableHealthTransition = true
		occurrence.family, occurrence.phase = sinkHealthV8Ready, "storage"
		occurrence.outcome, occurrence.severity = observability.OutcomeCompleted, "INFO"
		occurrence.subsystem, occurrence.healthState = "judge_bodies", "ready"
	case ActionGatewayJudgeStoreDrainTimeout:
		occurrence.family, occurrence.phase = sinkHealthV8Degraded, "drain"
		occurrence.outcome, occurrence.severity = observability.OutcomeFailed, "HIGH"
		occurrence.subsystem, occurrence.healthState = "judge_store", "degraded"
		occurrence.errorCode = observability.Present("drain_timeout")
	case ActionGatewayJudgeBodiesCloseError:
		occurrence.durableHealthTransition = true
		occurrence.family, occurrence.phase = sinkHealthV8Degraded, "shutdown"
		occurrence.outcome, occurrence.severity = observability.OutcomeFailed, "HIGH"
		occurrence.subsystem, occurrence.healthState = "judge_bodies", "degraded"
		occurrence.errorCode = observability.Present("close_failed")
	case ActionGatewayJudgeBodiesCloseSkipped:
		occurrence.durableHealthTransition = true
		occurrence.family, occurrence.phase = sinkHealthV8Degraded, "shutdown"
		occurrence.outcome, occurrence.severity = observability.OutcomeFailed, "HIGH"
		occurrence.subsystem, occurrence.healthState = "judge_bodies", "degraded"
		occurrence.errorCode = observability.Present("worker_still_running")
	default:
		return sinkHealthV8Occurrence{}, false
	}
	return occurrence, true
}

func buildSinkHealthV8Family(
	builder *observability.FamilyBuilder,
	envelope observability.FamilyEnvelopeInput,
	severity observability.Optional[observability.Severity],
	logLevel observability.Optional[observability.LogLevel],
	occurrence sinkHealthV8Occurrence,
) (observability.Record, error) {
	subsystem := occurrence.subsystem
	switch occurrence.family {
	case sinkHealthV8AuthenticationFailed:
		return builder.BuildLogDestinationAuthenticationFailed(
			observability.LogDestinationAuthenticationFailedInput{
				Envelope: envelope, Severity: severity, LogLevel: logLevel,
				Outcome: occurrence.outcome, DefenseClawHealthSubsystem: subsystem,
				DefenseClawHealthState:                occurrence.healthState,
				DefenseClawHealthErrorSummary:         occurrence.errorSummary,
				DefenseClawSchemaErrorCode:            occurrence.errorCode,
				MandatoryProtectedBoundaryAuthFailure: occurrence.protectedBoundaryAuthFailure,
			},
		)
	case sinkHealthV8AuthorizationDenied:
		return builder.BuildLogDestinationAuthorizationDenied(
			observability.LogDestinationAuthorizationDeniedInput{
				Envelope: envelope, Severity: severity, LogLevel: logLevel,
				Outcome: occurrence.outcome, DefenseClawHealthSubsystem: subsystem,
				DefenseClawHealthState:                occurrence.healthState,
				DefenseClawHealthErrorSummary:         occurrence.errorSummary,
				DefenseClawSchemaErrorCode:            occurrence.errorCode,
				MandatoryProtectedBoundaryAuthFailure: occurrence.protectedBoundaryAuthFailure,
			},
		)
	case sinkHealthV8ExportFailed:
		return builder.BuildLogDestinationExportFailed(observability.LogDestinationExportFailedInput{
			Envelope: envelope, Severity: severity, LogLevel: logLevel,
			Outcome: occurrence.outcome, DefenseClawHealthSubsystem: subsystem,
			DefenseClawHealthState:           occurrence.healthState,
			DefenseClawHealthErrorSummary:    occurrence.errorSummary,
			DefenseClawSchemaErrorCode:       occurrence.errorCode,
			MandatoryDurableHealthTransition: occurrence.durableHealthTransition,
		})
	case sinkHealthV8QueueFull:
		return builder.BuildLogDestinationQueueFull(observability.LogDestinationQueueFullInput{
			Envelope: envelope, Severity: severity, LogLevel: logLevel,
			Outcome: occurrence.outcome, DefenseClawHealthSubsystem: subsystem,
			DefenseClawHealthState:           occurrence.healthState,
			DefenseClawHealthErrorSummary:    occurrence.errorSummary,
			DefenseClawSchemaErrorCode:       occurrence.errorCode,
			MandatoryDurableHealthTransition: occurrence.durableHealthTransition,
		})
	case sinkHealthV8Degraded:
		return builder.BuildLogSubsystemDegraded(observability.LogSubsystemDegradedInput{
			Envelope: envelope, Severity: severity, LogLevel: logLevel,
			Outcome: occurrence.outcome, DefenseClawHealthSubsystem: subsystem,
			DefenseClawHealthState:           occurrence.healthState,
			DefenseClawHealthErrorSummary:    occurrence.errorSummary,
			DefenseClawSchemaErrorCode:       occurrence.errorCode,
			MandatoryDurableHealthTransition: occurrence.durableHealthTransition,
		})
	case sinkHealthV8Lifecycle:
		return builder.BuildLogSubsystemLifecycle(observability.LogSubsystemLifecycleInput{
			Envelope: envelope, Severity: severity, LogLevel: logLevel,
			Outcome: occurrence.outcome, DefenseClawHealthSubsystem: subsystem,
			DefenseClawHealthState:           occurrence.healthState,
			DefenseClawHealthErrorSummary:    occurrence.errorSummary,
			DefenseClawSchemaErrorCode:       occurrence.errorCode,
			MandatoryDurableHealthTransition: occurrence.durableHealthTransition,
		})
	case sinkHealthV8Ready:
		return builder.BuildLogSubsystemReady(observability.LogSubsystemReadyInput{
			Envelope: envelope, Severity: severity, LogLevel: logLevel,
			Outcome: occurrence.outcome, DefenseClawHealthSubsystem: subsystem,
			DefenseClawHealthState:           occurrence.healthState,
			DefenseClawHealthErrorSummary:    occurrence.errorSummary,
			DefenseClawSchemaErrorCode:       occurrence.errorCode,
			MandatoryDurableHealthTransition: occurrence.durableHealthTransition,
		})
	case sinkHealthV8Restored:
		return builder.BuildLogSubsystemRestored(observability.LogSubsystemRestoredInput{
			Envelope: envelope, Severity: severity, LogLevel: logLevel,
			Outcome: occurrence.outcome, DefenseClawHealthSubsystem: subsystem,
			DefenseClawHealthState:           occurrence.healthState,
			DefenseClawHealthErrorSummary:    occurrence.errorSummary,
			DefenseClawSchemaErrorCode:       occurrence.errorCode,
			MandatoryDurableHealthTransition: occurrence.durableHealthTransition,
		})
	default:
		return observability.Record{}, fmt.Errorf("audit: unsupported v8 sink health family")
	}
}

// platformHealthErrorSummary retains the source diagnostic until the central
// route applies its configured redaction profile. Keeping this value out of
// the producer's legacy sanitizer is what allows one destination to receive
// the raw diagnostic while another receives a field- or detector-redacted
// projection of the same occurrence.
func platformHealthErrorSummary(value string) observability.Optional[string] {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 65536 || !utf8.ValidString(value) {
		return observability.Absent[string]()
	}
	return observability.Present(value)
}

type sinkMetricV8Kind uint8

const (
	sinkMetricV8Invalid sinkMetricV8Kind = iota
	sinkMetricV8BatchDelivered
	sinkMetricV8BatchDropped
	sinkMetricV8DeliveryLatency
	sinkMetricV8Failure
	sinkMetricV8CircuitState
)

type sinkMetricV8Input struct {
	kind       sinkMetricV8Kind
	valueInt   int64
	valueFloat float64
	sinkKind   string
	sinkName   string
	reason     string
	statusCode int64
	retryCount int64
	action     string
	timestamp  time.Time
}

func newSinkRuntimeV8GeneratedMetric(input sinkMetricV8Input) (RuntimeV8GeneratedMetric, error) {
	family := sinkMetricV8Family(input.kind)
	if family == "" || input.valueInt < 0 || input.valueFloat < 0 ||
		input.statusCode < 0 || input.statusCode > 999 || input.retryCount < 0 {
		return RuntimeV8GeneratedMetric{}, fmt.Errorf("audit: invalid generated sink metric input")
	}
	return RuntimeV8GeneratedMetric{
		family: family,
		build: func(snapshot RuntimeV8BuildContext) (observability.Record, error) {
			return buildSinkRuntimeV8GeneratedMetric(snapshot, input)
		},
	}, nil
}

func sinkMetricV8Family(kind sinkMetricV8Kind) observability.EventName {
	switch kind {
	case sinkMetricV8BatchDelivered:
		return observability.EventName(observability.TelemetryInstrumentDefenseClawAuditSinkBatchesDelivered)
	case sinkMetricV8BatchDropped:
		return observability.EventName(observability.TelemetryInstrumentDefenseClawAuditSinkBatchesDropped)
	case sinkMetricV8DeliveryLatency:
		return observability.EventName(observability.TelemetryInstrumentDefenseClawAuditSinkDeliveryLatency)
	case sinkMetricV8Failure:
		return observability.EventName(observability.TelemetryInstrumentDefenseClawAuditSinkFailures)
	case sinkMetricV8CircuitState:
		return observability.EventName(observability.TelemetryInstrumentDefenseClawAuditSinkCircuitState)
	default:
		return ""
	}
}

func buildSinkRuntimeV8GeneratedMetric(
	snapshot RuntimeV8BuildContext,
	input sinkMetricV8Input,
) (observability.Record, error) {
	if snapshot.ConfigGeneration > math.MaxInt64 ||
		!observability.IsStableToken(snapshot.ConfigDigest) || input.timestamp.IsZero() {
		return observability.Record{}, fmt.Errorf("audit: invalid v8 sink metric build context")
	}
	builder, err := observability.NewFamilyBuilder(
		observability.ClockFunc(func() time.Time { return input.timestamp.UTC() }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) {
			return uuid.NewString(), nil
		}),
	)
	if err != nil {
		return observability.Record{}, err
	}
	envelope := observability.FamilyEnvelopeInput{
		ObservedAt: observability.Present(input.timestamp.UTC()),
		Source:     observability.SourceSystem, Action: input.action, Phase: "delivery",
		Correlation: observability.Correlation{
			RunID: currentRunID(), SidecarInstanceID: ProcessAgentInstanceID(),
		},
		Provenance: observability.FamilyProvenanceInput{
			Producer: "audit_logger", BinaryVersion: version.Current().BinaryVersion,
			ConfigGeneration: int64(snapshot.ConfigGeneration), ConfigDigest: snapshot.ConfigDigest,
		},
	}
	sinkKind := optionalSinkMetricDimension(input.sinkKind)
	sinkName := optionalSinkMetricDimension(input.sinkName)
	retryCount := observability.Present(input.retryCount)
	statusCode := observability.Present(input.statusCode)
	switch input.kind {
	case sinkMetricV8BatchDelivered:
		return builder.BuildMetricDefenseClawAuditSinkBatchesDelivered(
			observability.MetricDefenseClawAuditSinkBatchesDeliveredInput{
				Envelope: envelope, Value: input.valueInt,
				DefenseClawMetricKind: sinkKind, DefenseClawMetricSink: sinkName,
				DefenseClawMetricRetryCount: retryCount,
				DefenseClawMetricStatusCode: statusCode,
			},
		)
	case sinkMetricV8BatchDropped:
		return builder.BuildMetricDefenseClawAuditSinkBatchesDropped(
			observability.MetricDefenseClawAuditSinkBatchesDroppedInput{
				Envelope: envelope, Value: input.valueInt,
				DefenseClawMetricKind: sinkKind, DefenseClawMetricSink: sinkName,
				DefenseClawMetricRetryCount: retryCount,
				DefenseClawMetricStatusCode: statusCode,
			},
		)
	case sinkMetricV8DeliveryLatency:
		return builder.BuildMetricDefenseClawAuditSinkDeliveryLatency(
			observability.MetricDefenseClawAuditSinkDeliveryLatencyInput{
				Envelope: envelope, Value: input.valueFloat,
				DefenseClawMetricKind: sinkKind, DefenseClawMetricSink: sinkName,
				DefenseClawMetricRetryCount: retryCount,
				DefenseClawMetricStatusCode: statusCode,
			},
		)
	case sinkMetricV8Failure:
		return builder.BuildMetricDefenseClawAuditSinkFailures(
			observability.MetricDefenseClawAuditSinkFailuresInput{
				Envelope: envelope, Value: input.valueInt,
				DefenseClawMetricSinkKind: sinkKind, DefenseClawMetricSinkName: sinkName,
				DefenseClawMetricSinkReason: optionalSinkMetricDimension(input.reason),
			},
		)
	case sinkMetricV8CircuitState:
		return builder.BuildMetricDefenseClawAuditSinkCircuitState(
			observability.MetricDefenseClawAuditSinkCircuitStateInput{
				Envelope: envelope, Value: input.valueInt,
				DefenseClawMetricSinkKind: sinkKind, DefenseClawMetricSinkName: sinkName,
			},
		)
	default:
		return observability.Record{}, fmt.Errorf("audit: unsupported v8 sink metric family")
	}
}

func optionalSinkMetricDimension(value string) observability.Optional[string] {
	if !observability.IsStableToken(value) {
		return observability.Absent[string]()
	}
	return observability.Present(value)
}

func optionalAuditMetricDimension(value string) observability.Optional[string] {
	value = strings.TrimSpace(value)
	if value == "" || !utf8.ValidString(value) || len(value) > 256 {
		return observability.Absent[string]()
	}
	return observability.Present(value)
}

func newAuditEventRuntimeV8GeneratedMetric(event Event) (RuntimeV8GeneratedMetric, error) {
	if event.Timestamp.IsZero() || !observability.IsStableToken(event.Action) {
		return RuntimeV8GeneratedMetric{}, fmt.Errorf("audit: invalid generated audit-event metric input")
	}
	normalized := observability.NormalizeSeverity(event.Severity)
	if !normalized.Valid || !normalized.Present {
		return RuntimeV8GeneratedMetric{}, fmt.Errorf("audit: invalid generated audit-event severity")
	}
	connector := strings.TrimSpace(event.Connector)
	if !observability.IsStableToken(connector) {
		connector = "unknown"
	}
	return RuntimeV8GeneratedMetric{
		family: observability.EventName(observability.TelemetryInstrumentDefenseClawAuditEventsTotal),
		build: func(snapshot RuntimeV8BuildContext) (observability.Record, error) {
			if snapshot.ConfigGeneration > math.MaxInt64 ||
				!observability.IsStableToken(snapshot.ConfigDigest) {
				return observability.Record{}, fmt.Errorf("audit: invalid v8 audit-event metric build context")
			}
			builder, err := observability.NewFamilyBuilder(
				observability.ClockFunc(func() time.Time { return event.Timestamp.UTC() }),
				observability.OccurrenceIDGeneratorFunc(func() (string, error) { return uuid.NewString(), nil }),
			)
			if err != nil {
				return observability.Record{}, err
			}
			return builder.BuildMetricDefenseClawAuditEventsTotal(
				observability.MetricDefenseClawAuditEventsTotalInput{
					Envelope: observability.FamilyEnvelopeInput{
						ObservedAt: observability.Present(event.Timestamp.UTC()),
						Source:     observability.SourceSystem, Action: event.Action, Phase: "persistence",
						Correlation: controlPlaneV8Correlation(event),
						Provenance: observability.FamilyProvenanceInput{
							Producer: "audit_logger", BinaryVersion: version.Current().BinaryVersion,
							ConfigGeneration: int64(snapshot.ConfigGeneration), ConfigDigest: snapshot.ConfigDigest,
						},
					},
					Value:                       1,
					DefenseClawMetricAction:     optionalAuditMetricDimension(event.Action),
					DefenseClawConnectorSource:  observability.Present(connector),
					DefenseClawSecuritySeverity: observability.Present(string(normalized.Severity)),
				},
			)
		},
	}, nil
}

func newActivityRuntimeV8GeneratedMetrics(
	event Event,
	action string,
	targetType string,
	actor string,
	diffEntries int,
) ([]RuntimeV8GeneratedMetric, error) {
	if event.Timestamp.IsZero() || diffEntries < 0 {
		return nil, fmt.Errorf("audit: invalid generated activity metric input")
	}
	labels := struct {
		action     observability.Optional[string]
		targetType observability.Optional[string]
		actor      observability.Optional[string]
	}{
		action:     optionalAuditMetricDimension(action),
		targetType: optionalAuditMetricDimension(targetType),
		actor:      optionalAuditMetricDimension(actor),
	}
	build := func(
		family observability.EventName,
		value int64,
	) RuntimeV8GeneratedMetric {
		return RuntimeV8GeneratedMetric{
			family: family,
			build: func(snapshot RuntimeV8BuildContext) (observability.Record, error) {
				if snapshot.ConfigGeneration > math.MaxInt64 ||
					!observability.IsStableToken(snapshot.ConfigDigest) {
					return observability.Record{}, fmt.Errorf("audit: invalid v8 activity metric build context")
				}
				builder, err := observability.NewFamilyBuilder(
					observability.ClockFunc(func() time.Time { return event.Timestamp.UTC() }),
					observability.OccurrenceIDGeneratorFunc(func() (string, error) { return uuid.NewString(), nil }),
				)
				if err != nil {
					return observability.Record{}, err
				}
				envelope := observability.FamilyEnvelopeInput{
					ObservedAt: observability.Present(event.Timestamp.UTC()),
					Source:     observability.SourceSystem, Action: event.Action, Phase: "persistence",
					Correlation: controlPlaneV8Correlation(event),
					Provenance: observability.FamilyProvenanceInput{
						Producer: "audit_logger", BinaryVersion: version.Current().BinaryVersion,
						ConfigGeneration: int64(snapshot.ConfigGeneration), ConfigDigest: snapshot.ConfigDigest,
					},
				}
				switch family {
				case observability.EventName(observability.TelemetryInstrumentDefenseClawActivityTotal):
					return builder.BuildMetricDefenseClawActivityTotal(
						observability.MetricDefenseClawActivityTotalInput{
							Envelope: envelope, Value: value,
							DefenseClawMetricAction:     labels.action,
							DefenseClawMetricActor:      labels.actor,
							DefenseClawMetricTargetType: labels.targetType,
						},
					)
				case observability.EventName(observability.TelemetryInstrumentDefenseClawActivityDiffEntries):
					return builder.BuildMetricDefenseClawActivityDiffEntries(
						observability.MetricDefenseClawActivityDiffEntriesInput{
							Envelope: envelope, Value: value,
							DefenseClawMetricAction:     labels.action,
							DefenseClawMetricActor:      labels.actor,
							DefenseClawMetricTargetType: labels.targetType,
						},
					)
				default:
					return observability.Record{}, fmt.Errorf("audit: unsupported generated activity metric")
				}
			},
		}
	}
	return []RuntimeV8GeneratedMetric{
		build(observability.EventName(observability.TelemetryInstrumentDefenseClawActivityTotal), 1),
		build(observability.EventName(observability.TelemetryInstrumentDefenseClawActivityDiffEntries), int64(diffEntries)),
	}, nil
}

func (l *Logger) recordAuditEventMetricV8(
	ctx context.Context,
	binding runtimeV8Binding,
	event Event,
) error {
	metric, err := newAuditEventRuntimeV8GeneratedMetric(event)
	if err != nil {
		return err
	}
	return l.recordRuntimeV8GeneratedMetricBatch(ctx, binding, []RuntimeV8GeneratedMetric{metric})
}

func (l *Logger) recordRuntimeV8GeneratedMetricBatch(
	ctx context.Context,
	binding runtimeV8Binding,
	metrics []RuntimeV8GeneratedMetric,
) error {
	if binding.metricBatch == nil {
		return fmt.Errorf("audit: v8 generated metric batch runtime is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if len(metrics) == 0 || len(metrics) > 65_536 {
		return fmt.Errorf("audit: invalid generated metric batch")
	}
	for _, metric := range metrics {
		if metric.family == "" || metric.build == nil {
			return fmt.Errorf("audit: invalid generated metric batch")
		}
	}
	return binding.metricBatch.RecordRuntimeV8GeneratedMetricBatch(ctx, metrics)
}

func (l *Logger) recordSinkMetricV8(
	ctx context.Context,
	binding runtimeV8Binding,
	input sinkMetricV8Input,
) error {
	if binding.metricEmitter == nil {
		return fmt.Errorf("audit: v8 sink metric runtime is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	metric, err := newSinkRuntimeV8GeneratedMetric(input)
	if err != nil {
		return err
	}
	return binding.metricEmitter.RecordRuntimeV8GeneratedMetric(ctx, metric)
}
