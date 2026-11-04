// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

// HookFailureAuditRow is one locally delivered hook outcome read from the
// hook's append log. The reporter commits these rows in bounded groups.
type HookFailureAuditRow struct {
	Envelope CorrelationEnvelope
	Action   string
	Target   string
	Details  string
	Severity string
}

// LogHookFailureRowsAtomic returns the number of rows whose local outcome is
// settled. A failed local transaction settles none, so its source window can
// be replayed without duplicate rows.
func (l *Logger) LogHookFailureRowsAtomic(ctx context.Context, rows []HookFailureAuditRow) (int, error) {
	if ctx == nil || len(rows) == 0 || len(rows) > 32 {
		return 0, fmt.Errorf("audit: invalid hook failure batch")
	}
	binding := l.runtimeV8BindingSnapshot()
	atomicEmitter, ok := binding.emitter.(RuntimeV8AtomicLogBatchEmitter)
	if !ok {
		// Embedders with a single-record runtime still preserve the source
		// cursor after each completed append.
		for index, row := range rows {
			rowCtx := ContextWithEnvelope(ctx, row.Envelope)
			if err := l.LogActionCtxSeverity(rowCtx, row.Action, row.Target, row.Details, row.Severity); err != nil {
				return index, err
			}
		}
		return len(rows), nil
	}
	operations := make([]RuntimeV8LogOperation, 0, len(rows))
	events := make([]Event, 0, len(rows))
	mandatory := make([]bool, 0, len(rows))
	for _, row := range rows {
		if row.Action != string(ActionGuardrailBlock) && row.Action != string(ActionGuardrailWarn) {
			return 0, fmt.Errorf("audit: unsupported hook failure action")
		}
		severity := row.Severity
		if severity == "" {
			severity = "INFO"
		}
		event := Event{
			ID: observability.NewTimeOrderedID(), Timestamp: time.Now().UTC(),
			Action: row.Action, Target: row.Target, Actor: "defenseclaw",
			Details: row.Details, Severity: severity,
			SidecarInstanceID: ProcessAgentInstanceID(),
		}
		applyEnvelope(&event, row.Envelope)
		stampAuditEventEnvelope(&event)
		classification := observability.ClassificationContext{RawSeverity: event.Severity}
		registered, found := observability.AuditActionClassification(observability.ProducerKey(event.Action))
		if !found {
			return 0, fmt.Errorf("audit: hook failure action is not registered")
		}
		resolved, err := registered.Resolve(classification)
		if err != nil {
			return 0, fmt.Errorf("audit: classify hook failure action: %w", err)
		}
		source := controlPlaneV8Source(event, controlPlaneV8FamilyNone)
		metadata, err := router.NewClassifiedLogMetadata(
			observability.ProducerAuditAction, observability.ProducerKey(event.Action),
			classification, source, event.Connector, observability.ProducerKey(event.Action),
		)
		if err != nil {
			return 0, fmt.Errorf("audit: route hook failure action: %w", err)
		}
		operations = append(operations, RuntimeV8LogOperation{
			ctx: contextWithLegacyEventProjection(ctx, event), metadata: metadata,
			build: func(snapshot RuntimeV8BuildContext, admission router.Admission) (observability.Record, error) {
				return buildCompatibilityAuditV8Record(event, classification, source, "persistence", "", snapshot, admission)
			},
		})
		events = append(events, event)
		mandatory = append(mandatory, resolved.Mandatory)
	}
	outcomes, emitErr := atomicEmitter.EmitRuntimeV8AtomicLogBatch(contextWithLegacyEventProjectionBatch(ctx, events), operations)
	if len(outcomes) > len(rows) {
		return 0, fmt.Errorf("audit: atomic hook failure batch returned too many outcomes")
	}
	metrics := make([]RuntimeV8GeneratedMetric, 0, len(rows))
	settled := 0
	for index, outcome := range outcomes {
		disposition, err := runtimeV8Disposition(outcome, mandatory[index])
		if err != nil {
			return settled, fmt.Errorf("audit: hook failure row %d: %w", index, errors.Join(err, emitErr))
		}
		settled++
		if disposition == auditV8Persisted {
			if metric, metricErr := newAuditEventRuntimeV8GeneratedMetric(events[index]); metricErr == nil {
				metrics = append(metrics, metric)
			}
		}
	}
	if len(metrics) > 0 {
		_ = l.recordRuntimeV8GeneratedMetricBatch(ctx, binding, metrics)
	}
	if emitErr != nil {
		return settled, emitErr
	}
	if settled != len(rows) {
		return settled, fmt.Errorf("audit: atomic hook failure batch returned an incomplete outcome set")
	}
	return settled, nil
}
