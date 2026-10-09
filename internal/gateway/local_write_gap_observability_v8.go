// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/google/uuid"
)

const (
	localWriteGapV8Producer  = "gateway.local_history"
	localWriteGapV8Action    = "sqlite_write_failed"
	localWriteGapV8Subsystem = "local-sqlite"
)

// recordLocalWriteGapV8 runs when local history writes resume after a
// failure (disk full, read-only store). The optional destinations already
// received the records that local history lacks; one content-free
// sqlite.write_failed record says how many, so the gap in the audit export is
// not silent (GAP-1100). Secure Client keeps main's records (#1092).
func (s *Sidecar) recordLocalWriteGapV8() {
	if s == nil || ManagedEnterpriseActive() {
		return
	}
	s.observabilityV8Mu.Lock()
	owner, _ := s.observabilityV8.(*sidecarOwnedObservabilityV8Runtime)
	emitter := s.observabilityV8
	s.observabilityV8Mu.Unlock()
	if owner == nil || owner.runtime == nil || emitter == nil {
		return
	}
	lost := owner.runtime.TakeLocalWriteLosses()
	if lost == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := emitLocalWriteGapV8(ctx, emitter, lost, time.Now().UTC()); err != nil {
		owner.runtime.ReturnLocalWriteLosses(lost)
	}
}

func emitLocalWriteGapV8(ctx context.Context, emitter sidecarRuntimeEmitter, lost uint64, observedAt time.Time) error {
	if ctx == nil || emitter == nil || lost == 0 {
		return &sidecarObservabilityError{code: sidecarObservabilityInvalidBinding}
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
		return &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
	}
	noun := "records"
	if lost == 1 {
		noun = "record"
	}
	summary := fmt.Sprintf("%d log %s could not be stored in the local history while its SQLite writes failed; "+
		"the destinations that received them still have them", lost, noun)
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
	return err
}
