// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
)

// Candidate loading and policy generation can fail before the observability
// graph's Reload is reached. Persist those refusals through the active graph;
// the rejected candidate never supplies a projection or a destination.
func emitConfigReloadRejectionV8(ctx context.Context, emitter sidecarRuntimeEmitter, reason string) error {
	const action = observability.TelemetryEventConfigReloadRejected
	metadata, err := router.NewClassifiedLogMetadata(observability.ProducerAuditAction,
		observability.ProducerKey(audit.ActionConfigUpdate), observability.ClassificationContext{
			Bucket: observability.BucketComplianceActivity, EventName: observability.EventName(action),
			RawSeverity: "INFO", MandatoryFacts: observability.MandatoryFacts{ControlPlaneMutation: true},
		}, observability.SourceSystem, "", observability.ProducerKey(action))
	if err != nil {
		return err
	}
	_, err = emitter.Emit(ctx, metadata, func(snapshot observabilityruntime.EmitContext, _ router.Admission) (observability.Record, error) {
		builder, err := observability.NewFamilyBuilder(observability.ClockFunc(time.Now), observability.TimeOrderedOccurrenceIDs)
		if err != nil {
			return observability.Record{}, err
		}
		return builder.BuildLogConfigReloadRejected(observability.LogConfigReloadRejectedInput{
			Envelope: gatewayGeneratedEnvelope(ctx, snapshot, observability.SourceSystem, "", "gateway.config.reload", action, "validate"),
			Severity: observability.Present(observability.SeverityInfo), LogLevel: observability.Present(observability.LogLevelInfo),
			Outcome: observability.OutcomeRejected, DefenseClawAdminOperation: reason, MandatoryControlPlaneMutation: true,
		})
	})
	return err
}
