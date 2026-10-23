// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/google/uuid"
)

// logActivityImpl contains the Track 5 LogActivity body.
func (l *Logger) logActivityImpl(in ActivityInput) error {
	actor := in.Actor
	if actor == "" {
		actor = "system"
	}
	action := string(in.Action)
	if action == "" {
		// Fall back to the registered generic-mutation action rather
		// than a raw "activity" literal. Every value written to the
		// audit_events.action column must appear in AllActions() (and
		// in schemas/audit-event.json's action enum + Python parity)
		// so downstream SIEM filters and schema validators don't
		// reject the row. See scripts/check_audit_actions.py.
		action = string(ActionAction)
	}
	severity := in.Severity
	if severity == "" {
		severity = "INFO"
	}
	targetType := in.TargetType
	if targetType == "" {
		targetType = "unknown"
	}
	targetID := in.TargetID
	if targetID == "" {
		targetID = "unknown"
	}

	activityID := observability.NewTimeOrderedID()
	auditID := observability.NewTimeOrderedID()
	timestamp := time.Now().UTC()
	ctx := context.Background()
	stored := false
	var row storedOccurrence
	delivery := in.RemoteDelivery
	if in.OccurrenceID != "" {
		// The producer keeps this occurrence queued under its stable id and
		// offers it until it is stored durably and every remote destination
		// has it. The first offer stores it and exports it only after the
		// local write (a failed write exports nothing). A later offer finds
		// it stored and sends the stored record, with its stable ids, time
		// and the run, sidecar, binary and config of the process that stored
		// it, to the destinations that do not have it yet.
		auditID = in.OccurrenceID
		activityID = uuid.NewSHA1(stableOccurrenceNamespace, []byte("activity\x00"+auditID)).String()
		if delivery == nil {
			delivery = observability.NewRemoteDelivery()
		}
		found := false
		var err error
		row, found, err = l.store.storedOccurrence(ctx, auditID)
		if err != nil {
			return err
		}
		if found {
			stored, timestamp = true, row.timestamp
			// A row a stopped process committed may not be on disk yet.
			if err := l.syncOccurrence(ctx, delivery); err != nil {
				return err
			}
			ctx = withStoredOccurrence(observability.WithStoredReplayForm(ctx, row.floorOnly), row)
		} else {
			ctx = observability.WithExportAfterLocalWrite(ctx)
		}
		ctx = observability.WithRemoteDelivery(ctx, delivery)
		delivery.BeginAttempt()
		defer delivery.EndAttempt()
	}
	runID := in.RunID
	if runID == "" {
		runID = currentRunID()
	}

	summary := map[string]any{
		"activity_id":  activityID,
		"actor":        actor,
		"action":       action,
		"target_type":  targetType,
		"target_id":    targetID,
		"reason":       in.Reason,
		"before":       cloneStructuredPayload(in.Before),
		"after":        cloneStructuredPayload(in.After),
		"diff":         in.Diff,
		"version_from": in.VersionFrom,
		"version_to":   in.VersionTo,
	}
	summaryBlob, _ := json.Marshal(summary)

	// v7 clean break: AgentInstanceID is per-session (unset for
	// activity/mutation events that have no session anchor);
	// SidecarInstanceID carries the process UUID.
	auditEv := Event{
		ID:                auditID,
		Timestamp:         timestamp,
		Action:            action,
		Target:            targetType + ":" + targetID,
		Actor:             actor,
		Details:           string(summaryBlob),
		Severity:          severity,
		RunID:             runID,
		RequestID:         in.RequestID,
		TraceID:           in.TraceID,
		SidecarInstanceID: ProcessAgentInstanceID(),
	}
	stampAuditEventEnvelope(&auditEv)
	if stored {
		// A replay is the stored record: after a restart this process has
		// another run id, sidecar id, maybe binary, and the stamp fills an
		// empty value from this process.
		row.pin(&auditEv)
	}
	metricActor := actor
	if in.ConfigChange != nil {
		// The audit record keeps the OS account of a change; its counters
		// carry a fixed actor label, never an account name or SID.
		metricActor = configChangeMetricActor
	}
	activityMetrics, metricErr := newActivityRuntimeV8GeneratedMetrics(
		auditEv, action, targetType, metricActor, len(in.Diff),
	)
	if metricErr != nil {
		return metricErr
	}
	activityMetrics = append(activityMetrics, policyBundleReceiptMetrics(auditEv, in.BundleReceipt)...)
	evidence, evidenceErr := controlPlaneV8ActivityEvidence(in)
	if evidenceErr != nil {
		return evidenceErr
	}
	disposition, emitErr := l.emitControlPlaneV8WithEvidenceAndMetrics(
		ctx, auditEv, evidence, activityMetrics,
	)
	if emitErr != nil {
		return emitErr
	}
	// Runtime-handled activity occurrences exclusively own canonical SQLite and
	// optional destination fanout. The historical activity_events table is not
	// written by v8. The registered aggregate
	// metrics are emitted in one generated batch on the same runtime binding as
	// the canonical occurrence and remain exactly once for dashboard continuity.
	if disposition != auditV8Unhandled {
		return l.occurrenceStored(ctx, in.OccurrenceID != "" && !stored, delivery)
	}
	if stored {
		return fmt.Errorf("audit: no generated v8 family replays activity action %q", action)
	}
	disposition, emitErr = l.emitCompatibilityAuditV8(
		ctx, auditEv,
		compatibilityAuditV8Options{
			classification: observability.ClassificationContext{
				MandatoryFacts: observability.MandatoryFacts{ControlPlaneMutation: true},
			},
			phase: "apply", outcome: observability.OutcomeApplied,
			companionMetrics: activityMetrics,
		},
	)
	if emitErr != nil {
		return emitErr
	}
	if disposition != auditV8Unhandled {
		return l.occurrenceStored(ctx, in.OccurrenceID != "", delivery)
	}
	return fmt.Errorf("audit: no generated v8 family handled activity action %q", action)
}

// occurrenceStored makes a newly stored occurrence power-loss durable
// before its producer may mark it reported.
func (l *Logger) occurrenceStored(ctx context.Context, newlyStored bool, delivery *observability.RemoteDelivery) error {
	if !newlyStored {
		return nil
	}
	return l.syncOccurrence(ctx, delivery)
}

// syncOccurrence flushes the audit store once per delivery: the pool
// commits with synchronous=NORMAL, which a power loss can take back.
func (l *Logger) syncOccurrence(ctx context.Context, delivery *observability.RemoteDelivery) error {
	if delivery.LocalDurable() {
		return nil
	}
	if err := l.store.syncCommittedWrites(ctx); err != nil {
		return err
	}
	delivery.MarkLocalDurable()
	return nil
}
