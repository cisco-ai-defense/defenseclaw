// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/google/uuid"
)

const (
	localWriteGapV8Producer  = "gateway.local_history"
	localWriteGapV8Action    = "sqlite_write_failed"
	localWriteGapV8Subsystem = "local-sqlite"
)

// recordLocalWriteGapV8 runs when the gateway starts and when local history
// writes resume after a failure (disk full, read-only store). The optional
// destinations already received the records that local history lacks; one
// content-free sqlite.write_failed record says how many, so the gap in the
// audit export is not silent (GAP-1100). The count includes records an
// earlier gateway process lost before it crashed or stopped, which the loss
// journal in the data directory kept (GAP-1129). The losses are marked
// reported only once that record is stored in the local history, so a later
// restart does not report them again. Secure Client keeps main records (#1092).
func (s *Sidecar) recordLocalWriteGapV8() {
	if s == nil || ManagedEnterpriseActive() {
		return
	}
	// One report at a time: the start-up call and a write recovery must not
	// both report the same losses.
	s.localWriteGapV8Mu.Lock()
	defer s.localWriteGapV8Mu.Unlock()
	s.observabilityV8Mu.Lock()
	owner, _ := s.observabilityV8.(*sidecarOwnedObservabilityV8Runtime)
	emitter := s.observabilityV8
	s.observabilityV8Mu.Unlock()
	if owner == nil || owner.runtime == nil || emitter == nil {
		return
	}
	losses := owner.runtime.PendingLocalWriteLosses()
	if losses.Records == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	outcome, err := emitLocalWriteGapV8(ctx, emitter, losses, time.Now().UTC())
	if err == nil && outcome.LocalPersisted() {
		owner.runtime.ConsumeLocalWriteLosses(losses)
	}
}

// describeLocalWriteGapV8 is the record summary, for example "3 log records
// could not be stored in the local history while its SQLite writes failed
// (full 2, io 1; first 2026-10-09T10:00:00Z, last 2026-10-09T10:05:00Z; loss
// journal generation 0f3c...); the destinations that received them still
// have them". It names counts, reasons and times only.
func describeLocalWriteGapV8(losses observabilityruntime.LocalWriteLosses) string {
	noun := "records"
	if losses.Records == 1 {
		noun = "record"
	}
	var first, last time.Time
	reasons := make([]string, 0, len(losses.Reasons))
	for _, reason := range losses.Reasons {
		reasons = append(reasons, fmt.Sprintf("%s %d", reason.Reason, reason.Records))
		if first.IsZero() || reason.First.Before(first) {
			first = reason.First
		}
		if reason.Last.After(last) {
			last = reason.Last
		}
	}
	return fmt.Sprintf("%d log %s could not be stored in the local history while its SQLite writes failed "+
		"(%s; first %s, last %s; loss journal generation %s); the destinations that received them still have them",
		losses.Records, noun, strings.Join(reasons, ", "),
		first.UTC().Format(time.RFC3339), last.UTC().Format(time.RFC3339), losses.Generation)
}

func emitLocalWriteGapV8(
	ctx context.Context,
	emitter sidecarRuntimeEmitter,
	losses observabilityruntime.LocalWriteLosses,
	observedAt time.Time,
) (pipeline.LocalLogOutcome, error) {
	if ctx == nil || emitter == nil || losses.Records == 0 {
		return pipeline.LocalLogOutcome{}, &sidecarObservabilityError{code: sidecarObservabilityInvalidBinding}
	}
	producerKey := observability.ProducerKey(gatewaylog.EventError)
	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerGatewayEvent,
		producerKey,
		observability.ClassificationContext{
			Bucket:         observability.BucketPlatformHealth,
			EventName:      observability.EventName(observability.TelemetryEventSqliteWriteFailed),
			RawSeverity:    string(observability.SeverityHigh),
			MandatoryFacts: observability.MandatoryFacts{SQLiteFailure: true},
		},
		observability.SourceGateway,
		"",
		observability.ProducerKey(localWriteGapV8Action),
	)
	if err != nil {
		return pipeline.LocalLogOutcome{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
	}
	summary := describeLocalWriteGapV8(losses)
	return emitter.Emit(ctx, metadata, func(
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
		return builder.BuildLogSqliteWriteFailed(observability.LogSqliteWriteFailedInput{
			Envelope: gatewayGeneratedEnvelope(
				ctx, snapshot, observability.SourceGateway, "", localWriteGapV8Producer, localWriteGapV8Action, "persistence",
			),
			Severity:                      observability.Present(observability.SeverityHigh),
			LogLevel:                      observability.Present(observability.LogLevelError),
			Outcome:                       observability.OutcomeFailed,
			DefenseClawHealthSubsystem:    localWriteGapV8Subsystem,
			DefenseClawHealthState:        "failed",
			DefenseClawHealthErrorSummary: observability.Present(summary),
			DefenseClawSchemaErrorCode:    observability.Present(localWriteGapV8Action),
			MandatorySqliteFailure:        true,
		})
	})
}
