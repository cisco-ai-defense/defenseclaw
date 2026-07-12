// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

// AssetLifecycleInput contains only identity and transition facts reported by
// the producer. In particular, callers cannot ask this adapter to synthesize an
// asset ID, version, state transition, or duration.
type AssetLifecycleInput struct {
	AssetID    string
	AssetType  string
	TargetRef  string
	TargetPath string
	Reason     string
	Initiator  string
}

// LogAssetDiscoveredCtx supplies the source-backed identity facts required by
// the generated asset.discovered family while retaining the local event-history
// compatibility projection used by existing queries. It is required when
// Event.Target is a path rather than the stable asset identifier.
func (l *Logger) LogAssetDiscoveredCtx(
	ctx context.Context,
	target, details string,
	input AssetLifecycleInput,
) error {
	return l.logActionWithEnvelopeContextAndAsset(
		ctx, EnvelopeFromContext(ctx), string(ActionInstallDetected), target, details, "INFO", &input,
	)
}

func (l *Logger) emitAssetLifecycleV8(
	ctx context.Context,
	event Event,
	input AssetLifecycleInput,
	mapping telemetry.AssetLifecycleActionMapping,
	emitter RuntimeV8Emitter,
) (auditV8Disposition, error) {
	if emitter == nil {
		return auditV8Persisted, fmt.Errorf("audit: asset lifecycle v8 runtime is unavailable")
	}
	if mapping.CanonicalEvent == "" {
		return auditV8Unhandled, nil
	}
	if err := validateAssetLifecycleInput(input); err != nil {
		return auditV8Persisted, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	source := observability.SourceWatcher
	classification := observability.ClassificationContext{
		EventName:   observability.EventName(mapping.CanonicalEvent),
		RawSeverity: event.Severity,
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
		return auditV8Persisted, fmt.Errorf("audit: classify asset lifecycle action %q: %w", event.Action, err)
	}
	correlation := controlPlaneV8Correlation(event)
	result, err := emitter.EmitRuntimeV8(
		contextWithLegacyEventProjection(ctx, event), metadata,
		func(snapshot RuntimeV8BuildContext, admission router.Admission) (observability.Record, error) {
			if admission != router.AdmissionOrdinary {
				return observability.Record{}, fmt.Errorf("audit: asset discovery requires ordinary admission")
			}
			builder, envelope, severity, logLevel, buildErr := runtimeV8FamilyBuildState(
				event, snapshot, source, mapping.Transition, correlation,
			)
			if buildErr != nil {
				return observability.Record{}, buildErr
			}
			record, buildErr := buildAssetLifecycleFamily(
				builder, envelope, severity, logLevel, input, mapping,
			)
			return verifyRuntimeV8Record(record, buildErr, event, false)
		},
	)
	if err != nil {
		return auditV8Persisted, fmt.Errorf("audit: emit asset lifecycle action %q: %w", event.Action, err)
	}
	return runtimeV8Disposition(result, false)
}

func buildAssetLifecycleFamily(
	builder *observability.FamilyBuilder,
	envelope observability.FamilyEnvelopeInput,
	severity observability.Optional[observability.Severity],
	logLevel observability.Optional[observability.LogLevel],
	input AssetLifecycleInput,
	mapping telemetry.AssetLifecycleActionMapping,
) (observability.Record, error) {
	assetType := optionalAssetLifecycleType(input.AssetType)
	targetRef := optionalAssetLifecycleIdentifier(input.TargetRef, 512)
	targetPath := optionalAssetLifecycleText(input.TargetPath)
	reason := optionalAssetLifecycleText(input.Reason)
	initiator := optionalAssetLifecycleIdentifier(input.Initiator, 512)

	switch mapping.CanonicalEvent {
	case observability.TelemetryEventAssetDiscovered:
		return builder.BuildLogAssetDiscovered(observability.LogAssetDiscoveredInput{
			Envelope: envelope, Severity: severity, LogLevel: logLevel,
			DefenseClawAssetID: input.AssetID, DefenseClawAssetType: assetType,
			DefenseClawAssetTransition: mapping.Transition, DefenseClawAssetTargetRef: targetRef,
			DefenseClawAssetTargetPath: targetPath, DefenseClawAssetTransitionReason: reason,
			DefenseClawAssetTransitionInitiator: initiator,
			MandatoryEnforcementStateChange:     false,
		})
	default:
		return observability.Record{}, fmt.Errorf("audit: unsupported canonical asset lifecycle event")
	}
}

func validateAssetLifecycleInput(input AssetLifecycleInput) error {
	if !runtimeV8Identifier(input.AssetID) {
		return fmt.Errorf("audit: asset lifecycle requires a source-backed stable asset ID")
	}
	if input.AssetType != "" && !validAssetLifecycleType(input.AssetType) {
		return fmt.Errorf("audit: invalid asset lifecycle type")
	}
	for name, value := range map[string]string{
		"target_ref": input.TargetRef,
		"initiator":  input.Initiator,
	} {
		if value != "" && (!utf8.ValidString(value) || !controlPlaneV8PrincipalPattern.MatchString(value)) {
			return fmt.Errorf("audit: invalid asset lifecycle %s", name)
		}
	}
	return nil
}

func validAssetLifecycleType(value string) bool {
	switch value {
	case "skill", "plugin", "mcp", "model", "connector":
		return true
	default:
		return false
	}
}

func optionalAssetLifecycleType(value string) observability.Optional[string] {
	if !validAssetLifecycleType(value) {
		return observability.Absent[string]()
	}
	return observability.Present(value)
}

func optionalAssetLifecycleIdentifier(value string, maximum int) observability.Optional[string] {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maximum || !utf8.ValidString(value) || !controlPlaneV8PrincipalPattern.MatchString(value) {
		return observability.Absent[string]()
	}
	return observability.Present(value)
}

func optionalAssetLifecycleText(value string) observability.Optional[string] {
	if strings.TrimSpace(value) == "" {
		return observability.Absent[string]()
	}
	return observability.Present(value)
}
