// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"context"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	v8redaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	legacyredaction "github.com/defenseclaw/defenseclaw/internal/redaction"
)

// ProjectManagedLog derives only the immutable managed destination representation.
// It never appends a local row, writes a diagnostic, or offers dispatcher work.
// Manifest recovery uses it to bind legacy submitted parts without replaying text.
func (pipeline *LocalLogPipeline) ProjectManagedLog(ctx context.Context, metadata router.Metadata, builder router.RecordBuilder) (LocalLogOutcome, error) {
	if pipeline == nil || pipeline.evaluator == nil || pipeline.projector == nil || builder == nil {
		return LocalLogOutcome{}, &Error{code: ErrorInvalidDependency}
	}
	if ctx == nil || metadata.Identity().Signal != observability.SignalLogs {
		return LocalLogOutcome{}, &Error{code: ErrorInvalidInput}
	}
	if err := ctx.Err(); err != nil {
		return LocalLogOutcome{}, &Error{code: ErrorContextDone, contextCause: err}
	}
	result, err := pipeline.evaluator.Evaluate(metadata, builder)
	if err != nil {
		return LocalLogOutcome{}, &Error{code: ErrorEvaluation}
	}
	if result.Admission() == router.AdmissionDrop {
		return pipeline.ProcessManagedLogFallback(ctx, metadata, builder)
	}
	outcome := LocalLogOutcome{admission: result.Admission()}
	record, ok := result.Record()
	if !ok {
		return LocalLogOutcome{}, &Error{code: ErrorEvaluation}
	}
	for _, route := range result.Deliveries() {
		if route.DestinationName != config.ObservabilityV8ManagedAIDDestinationName {
			continue
		}
		if route.DestinationKind != config.ObservabilityV8DestinationOTLP || route.MandatoryFloor || route.RedactionProfile != string(v8redaction.ProfileSensitive) {
			return LocalLogOutcome{}, &Error{code: ErrorEvaluation}
		}
		profile, found := pipeline.resolveProjectionProfile(v8redaction.ProfileSensitive, legacyredaction.SinkPolicyFromContext(ctx))
		if !found {
			return LocalLogOutcome{}, &Error{code: ErrorLocalProfile}
		}
		projection, _, err := pipeline.projector.Project(record, profile)
		if err != nil {
			return LocalLogOutcome{}, &Error{code: ErrorLocalProjection}
		}
		outcome.optionalWork = []ProjectedDelivery{{delivery: route, projection: projection, identity: ProjectedDeliveryIdentity{recordID: record.RecordID(), bucket: record.Bucket(), signal: record.Signal(), eventName: record.EventName()}}}
		return outcome, nil
	}
	return outcome, nil
}
