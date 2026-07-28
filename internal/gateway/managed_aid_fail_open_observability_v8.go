// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"math"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/version"
	"github.com/google/uuid"
)

const managedAIDFailOpenV8Producer = "gateway.managed_aid_fail_open"

func managedAIDFailOpenSeverity(reason string) (observability.Severity, observability.LogLevel) {
	if reason == aidFailOpenNoContent {
		return observability.SeverityInfo, observability.LogLevelInfo
	}
	return observability.SeverityHigh, observability.LogLevelWarn
}

func managedAIDFailOpenAvailabilityFailure(reason string) bool {
	return reason == aidFailOpenUnwired || reason == aidFailOpenUnavailable
}

func normalizeManagedAIDFailOpenReason(reason string) string {
	switch strings.TrimSpace(reason) {
	case aidFailOpenUnwired, aidFailOpenUnavailable, aidFailOpenNoContent:
		return strings.TrimSpace(reason)
	default:
		return "unknown"
	}
}

func normalizeManagedAIDFailOpenDirection(direction string) string {
	switch strings.ToLower(strings.TrimSpace(direction)) {
	case "prompt", "completion", "tool_call", "tool_result":
		return strings.ToLower(strings.TrimSpace(direction))
	default:
		return "unknown"
	}
}

// emitManagedAIDFailOpenV8 separates availability failures from the benign
// no-content skip. Unwired and unavailable AID inspection are bounded platform
// health failures with a typed mandatory floor. No-content remains an opt-in
// INFO diagnostic because it is neither a failure nor a degraded subsystem.
func emitManagedAIDFailOpenV8(
	ctx context.Context,
	emitter sidecarRuntimeEmitter,
	reason string,
	direction string,
) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if emitter == nil {
		return &sidecarObservabilityError{code: sidecarObservabilityInvalidBinding}
	}
	reason = normalizeManagedAIDFailOpenReason(reason)
	direction = normalizeManagedAIDFailOpenDirection(direction)
	if !managedAIDFailOpenAvailabilityFailure(reason) {
		return emitManagedAIDFailOpenDiagnosticV8(ctx, emitter, reason, direction)
	}
	return emitManagedAIDFailOpenAvailabilityV8(ctx, emitter, reason, direction)
}

func emitManagedAIDFailOpenAvailabilityV8(
	ctx context.Context,
	emitter sidecarRuntimeEmitter,
	reason string,
	direction string,
) error {
	severity, logLevel := managedAIDFailOpenSeverity(reason)
	observedAt := time.Now().UTC()
	producerKey := observability.ProducerKey(gatewaylog.EventManagedAIDFailOpen)
	classification := observability.ClassificationContext{
		Bucket:      observability.BucketPlatformHealth,
		EventName:   observability.EventName(observability.TelemetryEventSubsystemDegraded),
		RawSeverity: string(severity),
		MandatoryFacts: observability.MandatoryFacts{
			ManagedAIDFailOpen: true,
		},
	}
	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerGatewayEvent,
		producerKey,
		classification,
		observability.SourceGateway,
		"",
		observability.ProducerKey("allow"),
	)
	if err != nil {
		return err
	}
	_, err = emitter.Emit(ctx, metadata, func(
		snapshot observabilityruntime.EmitContext,
		admission router.Admission,
	) (observability.Record, error) {
		if snapshot.Generation() > math.MaxInt64 ||
			(admission != router.AdmissionOrdinary && admission != router.AdmissionFloor) {
			return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
		}
		if admission == router.AdmissionFloor {
			builder, buildErr := observability.NewRecordBuilder(
				observability.ClockFunc(func() time.Time { return observedAt }),
				observability.OccurrenceIDGeneratorFunc(func() (string, error) { return uuid.NewString(), nil }),
			)
			if buildErr != nil {
				return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
			}
			return builder.BuildMandatoryFloorLog(observability.MandatoryFloorLogInput{
				ProducerKind:          observability.ProducerGatewayEvent,
				ProducerKey:           producerKey,
				ClassificationContext: classification,
				ObservedAt:            &observedAt,
				Source:                observability.SourceGateway,
				Action:                "allow",
				Phase:                 direction,
				Outcome:               observability.OutcomeFailed,
				Correlation:           gatewayGeneratedCorrelation(ctx, ""),
				Provenance: observability.Provenance{
					Producer: managedAIDFailOpenV8Producer, BinaryVersion: version.Current().BinaryVersion,
					RegistrySchemaVersion: observability.CurrentRecordSchemaVersion,
					ConfigGeneration:      int64(snapshot.Generation()), ConfigDigest: snapshot.Digest(),
				},
			})
		}
		builder, buildErr := observability.NewFamilyBuilder(
			observability.ClockFunc(func() time.Time { return observedAt }),
			observability.OccurrenceIDGeneratorFunc(func() (string, error) { return uuid.NewString(), nil }),
		)
		if buildErr != nil {
			return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
		}
		envelope := gatewayGeneratedEnvelope(
			ctx, snapshot, observability.SourceGateway, "", managedAIDFailOpenV8Producer, "allow", direction,
		)
		envelope.ObservedAt = observability.Present(observedAt)
		return builder.BuildLogSubsystemDegraded(observability.LogSubsystemDegradedInput{
			Envelope:                         envelope,
			Severity:                         observability.Present(severity),
			LogLevel:                         observability.Present(logLevel),
			Outcome:                          observability.OutcomeFailed,
			DefenseClawHealthSubsystem:       managedAIDFailOpenComponent + "." + reason,
			DefenseClawHealthState:           "degraded",
			DefenseClawSchemaErrorCode:       observability.Present(reason),
			MandatoryManagedAidFailOpen:      true,
			MandatoryDurableHealthTransition: false,
		})
	})
	return err
}

func emitManagedAIDFailOpenDiagnosticV8(
	ctx context.Context,
	emitter sidecarRuntimeEmitter,
	reason string,
	direction string,
) error {
	severity, logLevel := managedAIDFailOpenSeverity(reason)
	observedAt := time.Now().UTC()
	producerKey := observability.ProducerKey(gatewaylog.EventDiagnostic)
	classification := observability.ClassificationContext{
		Bucket: observability.BucketDiagnostic,
		EventName: observability.EventName(
			observability.TelemetryEventDiagnosticMessage,
		),
		RawSeverity: string(severity),
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
		return err
	}
	_, err = emitter.Emit(ctx, metadata, func(
		snapshot observabilityruntime.EmitContext,
		admission router.Admission,
	) (observability.Record, error) {
		if admission != router.AdmissionOrdinary || snapshot.Generation() > math.MaxInt64 {
			return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
		}
		builder, buildErr := observability.NewFamilyBuilder(
			observability.ClockFunc(func() time.Time { return observedAt }),
			observability.OccurrenceIDGeneratorFunc(func() (string, error) { return uuid.NewString(), nil }),
		)
		if buildErr != nil {
			return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
		}
		envelope := gatewayGeneratedEnvelope(
			ctx, snapshot, observability.SourceGateway, "", managedAIDFailOpenV8Producer, "allow", direction,
		)
		envelope.ObservedAt = observability.Present(observedAt)
		return builder.BuildLogDiagnosticMessage(observability.LogDiagnosticMessageInput{
			Envelope:                       envelope,
			Severity:                       observability.Present(severity),
			LogLevel:                       observability.Present(logLevel),
			DefenseClawDiagnosticComponent: managedAIDFailOpenComponent + "." + reason,
			DefenseClawDiagnosticMessage: observability.Present(
				"managed AID inspection skipped because no content was available",
			),
		})
	})
	return err
}
