// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"math"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/version"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"
)

const (
	platformHealthV8Producer = "gateway.platform_health"
	configMetricV8Producer   = "gateway.config_manager"
)

// recordGatewayPanicV8 preserves both halves of the recovered-panic contract:
// a low-cardinality counter for alerting and a durable, content-free health
// transition for forensic review. The recovered value and stack never enter
// telemetry. Request-scoped callers retain their exact W3C and DefenseClaw
// correlation identifiers.
func recordGatewayPanicV8(
	ctx context.Context,
	emitter sidecarRuntimeEmitter,
	metricRuntime hookLifecycleMetricV8Runtime,
) {
	if ctx == nil {
		return
	}
	observedAt := time.Now().UTC()
	recordGatewayPanicMetricV8(ctx, metricRuntime, observedAt)
	_ = emitGatewayPanicHealthV8(ctx, emitter, observedAt)
}

func recordGatewayPanicMetricV8(
	ctx context.Context,
	metricRuntime hookLifecycleMetricV8Runtime,
	observedAt time.Time,
) {
	if ctx != nil && metricRuntime != nil {
		panicItem := newGatewayGeneratedMetricItem(
			ctx, observedAt, observability.SourceGateway, "", platformHealthV8Producer,
			observability.EventName(observability.TelemetryInstrumentDefenseClawPanicsTotal),
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
				return builder.BuildMetricDefenseClawPanicsTotal(observability.MetricDefenseClawPanicsTotalInput{
					Envelope: envelope, Value: 1,
					DefenseClawMetricSubsystem: observability.Present(string(gatewaylog.SubsystemGateway)),
				})
			},
		)
		errorItem := gatewayErrorMetricItem(
			ctx, observedAt, string(gatewaylog.SubsystemGateway), string(gatewaylog.ErrCodePanicRecovered),
		)
		_, _ = metricRuntime.RecordGeneratedMetricBatch(
			ctx, []observabilityruntime.GeneratedMetricBatchItem{panicItem, errorItem},
		)
	}
}

func recordConfigLoadErrorV8(
	ctx context.Context,
	metricRuntime hookLifecycleMetricV8Runtime,
	errorType string,
) {
	if ctx == nil || metricRuntime == nil {
		return
	}
	item := newGatewayGeneratedMetricItem(
		ctx, time.Now().UTC(), observability.SourceSystem, "", configMetricV8Producer,
		observability.EventName(observability.TelemetryInstrumentDefenseClawConfigLoadErrors),
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			return builder.BuildMetricDefenseClawConfigLoadErrors(
				observability.MetricDefenseClawConfigLoadErrorsInput{
					Envelope: envelope, Value: 1,
					DefenseClawMetricErrorType: hookV8OptionalText(errorType, 256),
				},
			)
		},
	)
	_, _ = metricRuntime.RecordGeneratedMetricBatch(
		ctx, []observabilityruntime.GeneratedMetricBatchItem{item},
	)
}

func gatewayErrorMetricItem(
	ctx context.Context,
	observedAt time.Time,
	subsystem string,
	code string,
) observabilityruntime.GeneratedMetricBatchItem {
	return newGatewayGeneratedMetricItem(
		ctx, observedAt, observability.SourceGateway, "", platformHealthV8Producer,
		observability.EventName(observability.TelemetryInstrumentDefenseClawGatewayErrors),
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			return builder.BuildMetricDefenseClawGatewayErrors(
				observability.MetricDefenseClawGatewayErrorsInput{
					Envelope: envelope, Value: 1,
					DefenseClawMetricErrorCode:      hookV8OptionalText(code, 256),
					DefenseClawMetricErrorSubsystem: hookV8OptionalText(subsystem, 256),
				},
			)
		},
	)
}

func recordGatewayErrorV8(
	ctx context.Context,
	metricRuntime hookLifecycleMetricV8Runtime,
	subsystem string,
	code string,
) {
	if ctx == nil || metricRuntime == nil {
		return
	}
	_, _ = metricRuntime.RecordGeneratedMetricBatch(
		ctx, []observabilityruntime.GeneratedMetricBatchItem{
			gatewayErrorMetricItem(ctx, time.Now().UTC(), subsystem, code),
		},
	)
}

func recordAuditDBErrorV8(
	ctx context.Context,
	metricRuntime hookLifecycleMetricV8Runtime,
	operation string,
) {
	if ctx == nil || metricRuntime == nil {
		return
	}
	observedAt := time.Now().UTC()
	connector := hookDecisionMetricConnector(audit.EnvelopeFromContext(ctx).Connector)
	item := newGatewayGeneratedMetricItem(
		ctx, observedAt, observability.SourceGateway, connector, platformHealthV8Producer,
		observability.EventName(observability.TelemetryInstrumentDefenseClawAuditDBErrors),
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			return builder.BuildMetricDefenseClawAuditDBErrors(observability.MetricDefenseClawAuditDBErrorsInput{
				Envelope: envelope, Value: 1,
				DefenseClawMetricOperation: hookV8OptionalText(operation, 256),
			})
		},
	)
	errorItem := gatewayErrorMetricItem(ctx, observedAt, "audit", "AUDIT_DB_ERROR")
	_, _ = metricRuntime.RecordGeneratedMetricBatch(
		ctx, []observabilityruntime.GeneratedMetricBatchItem{item, errorItem},
	)
}

func emitGatewayPanicHealthV8(
	ctx context.Context,
	emitter sidecarRuntimeEmitter,
	observedAt time.Time,
) error {
	if ctx == nil || emitter == nil {
		return &sidecarObservabilityError{code: sidecarObservabilityInvalidBinding}
	}

	producerKey := observability.ProducerKey(gatewaylog.EventError)
	classification := observability.ClassificationContext{
		Bucket:      observability.BucketPlatformHealth,
		EventName:   observability.EventName(observability.TelemetryEventSubsystemDegraded),
		RawSeverity: "ERROR",
		MandatoryFacts: observability.MandatoryFacts{
			DurableHealthTransition: true,
		},
	}
	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerGatewayEvent,
		producerKey,
		classification,
		observability.SourceGateway,
		"",
		producerKey,
	)
	if err != nil {
		return &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
	}
	_, err = emitter.Emit(ctx, metadata, func(
		snapshot observabilityruntime.EmitContext,
		admission router.Admission,
	) (observability.Record, error) {
		if snapshot.Generation() > math.MaxInt64 ||
			(admission != router.AdmissionOrdinary && admission != router.AdmissionFloor) {
			return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
		}
		builder, buildErr := observability.NewFamilyBuilder(
			observability.ClockFunc(func() time.Time { return observedAt }),
			observability.OccurrenceIDGeneratorFunc(func() (string, error) { return uuid.NewString(), nil }),
		)
		if buildErr != nil {
			return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
		}
		return builder.BuildLogSubsystemDegraded(observability.LogSubsystemDegradedInput{
			Envelope: gatewayGeneratedEnvelope(
				ctx, snapshot, observability.SourceGateway, "", platformHealthV8Producer, "error", "evaluation",
			),
			Severity:                         observability.Present(observability.SeverityHigh),
			LogLevel:                         observability.Present(observability.LogLevelError),
			Outcome:                          observability.OutcomeFailed,
			DefenseClawHealthSubsystem:       string(gatewaylog.SubsystemGateway),
			DefenseClawHealthState:           "failed",
			DefenseClawSchemaErrorCode:       observability.Present(string(gatewaylog.ErrCodePanicRecovered)),
			MandatoryDurableHealthTransition: true,
		})
	})
	if err != nil {
		return err
	}
	return nil
}

func recordWatcherErrorV8(ctx context.Context, runtime hookLifecycleMetricV8Runtime) {
	if err := recordWatcherMetricV8(ctx, runtime, observability.TelemetryInstrumentDefenseClawWatcherErrors, "", "", ""); err == nil && ctx != nil && runtime != nil {
		_, _ = runtime.RecordGeneratedMetricBatch(ctx, []observabilityruntime.GeneratedMetricBatchItem{
			gatewayErrorMetricItem(ctx, time.Now().UTC(), string(gatewaylog.SubsystemWatcher), "WATCHER_ERROR"),
		})
	}
}

func recordWatcherRestartV8(ctx context.Context, runtime hookLifecycleMetricV8Runtime) error {
	return recordWatcherMetricV8(ctx, runtime, observability.TelemetryInstrumentDefenseClawWatcherRestarts, "", "", "")
}

func recordWatcherEventV8(
	ctx context.Context,
	runtime hookLifecycleMetricV8Runtime,
	eventType string,
	targetType string,
	connector string,
) {
	_ = recordWatcherMetricV8(
		ctx, runtime, observability.TelemetryInstrumentDefenseClawWatcherEvents,
		eventType, targetType, hookDecisionMetricConnector(connector),
	)
}

func recordWatcherMetricV8(
	ctx context.Context,
	runtime hookLifecycleMetricV8Runtime,
	family string,
	eventType string,
	targetType string,
	connector string,
) error {
	if ctx == nil || runtime == nil {
		return &sidecarObservabilityError{code: sidecarObservabilityInvalidBinding}
	}
	observedAt := time.Now().UTC()
	item := newGatewayGeneratedMetricItem(
		ctx, observedAt, observability.SourceWatcher, connector, platformHealthV8Producer, observability.EventName(family),
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			switch family {
			case observability.TelemetryInstrumentDefenseClawWatcherErrors:
				return builder.BuildMetricDefenseClawWatcherErrors(observability.MetricDefenseClawWatcherErrorsInput{
					Envelope: envelope, Value: 1,
				})
			case observability.TelemetryInstrumentDefenseClawWatcherEvents:
				return builder.BuildMetricDefenseClawWatcherEvents(observability.MetricDefenseClawWatcherEventsInput{
					Envelope: envelope, Value: 1,
					DefenseClawConnectorSource:  observability.Present(connector),
					DefenseClawMetricEventType:  observability.Present(eventType),
					DefenseClawMetricTargetType: observability.Present(targetType),
				})
			case observability.TelemetryInstrumentDefenseClawWatcherRestarts:
				return builder.BuildMetricDefenseClawWatcherRestarts(observability.MetricDefenseClawWatcherRestartsInput{
					Envelope: envelope, Value: 1,
				})
			default:
				return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
			}
		},
	)
	_, err := runtime.RecordGeneratedMetricBatch(ctx, []observabilityruntime.GeneratedMetricBatchItem{item})
	return err
}

func newGatewayGeneratedMetricItem(
	ctx context.Context,
	observedAt time.Time,
	source observability.Source,
	connector string,
	producer string,
	family observability.EventName,
	build hookV8MetricRecordBuilder,
) observabilityruntime.GeneratedMetricBatchItem {
	return observabilityruntime.GeneratedMetricBatchItem{
		Family: family,
		Builder: func(snapshot observabilityruntime.EmitContext) (observability.Record, error) {
			if snapshot.Generation() > math.MaxInt64 || build == nil {
				return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
			}
			builder, err := observability.NewFamilyBuilder(
				observability.ClockFunc(func() time.Time { return observedAt }),
				observability.OccurrenceIDGeneratorFunc(func() (string, error) { return uuid.NewString(), nil }),
			)
			if err != nil {
				return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
			}
			return build(builder, gatewayGeneratedEnvelope(ctx, snapshot, source, connector, producer, "", ""))
		},
	}
}

func gatewayGeneratedEnvelope(
	ctx context.Context,
	snapshot observabilityruntime.EmitContext,
	source observability.Source,
	connector string,
	producer string,
	action string,
	phase string,
) observability.FamilyEnvelopeInput {
	return observability.FamilyEnvelopeInput{
		Source: source, Connector: connector, Action: action, Phase: phase,
		Correlation: gatewayGeneratedCorrelation(ctx, connector),
		Provenance: observability.FamilyProvenanceInput{
			Producer: producer, BinaryVersion: version.Current().BinaryVersion,
			ConfigGeneration: int64(snapshot.Generation()), ConfigDigest: snapshot.Digest(),
		},
	}
}

func gatewayGeneratedCorrelation(
	ctx context.Context,
	connector string,
) observability.Correlation {
	legacy := audit.EnvelopeFromContext(ctx)
	identity := AgentIdentityFromContext(ctx)
	correlation := observability.Correlation{
		RunID:     firstNonEmpty(legacy.RunID, gatewaylog.ProcessRunID()),
		RequestID: legacy.RequestID, SessionID: legacy.SessionID, TurnID: legacy.TurnID,
		TraceID:          legacy.TraceID,
		AgentID:          firstNonEmpty(identity.AgentID, legacy.AgentID),
		AgentInstanceID:  firstNonEmpty(identity.AgentInstanceID, legacy.AgentInstanceID),
		PolicyID:         legacy.PolicyID,
		ToolInvocationID: legacy.ToolID, ConnectorID: connector,
		SidecarInstanceID: gatewaylog.SidecarInstanceID(),
	}
	if spanContext := trace.SpanContextFromContext(ctx); spanContext.IsValid() {
		correlation.TraceID = spanContext.TraceID().String()
		correlation.SpanID = spanContext.SpanID().String()
	}
	return correlation
}
