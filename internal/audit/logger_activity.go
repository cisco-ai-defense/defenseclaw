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
	var spooled *spooledChange
	// localErr is the audit store's failure to answer for a spooled
	// occurrence: the offer still goes to the remote destinations, and the
	// call fails so the producer keeps it until the row is durable.
	var localErr error
	if in.OccurrenceID != "" {
		// The producer keeps this occurrence in its durable spool under a
		// stable id (the hash of its content) and its one sender offers it
		// until every sink has it: the audit store, and each remote
		// destination (observability.RemoteDelivery), each on its own.
		// Every offer is the same record: it is built from the occurrence
		// (its id, time and content) and its pin (the run, sidecar, binary
		// and config of the first offer, flushed before any sink got it),
		// and sent only when it is the pinned record. An offer writes the
		// row unless the store holds it (then the row must be the record),
		// and goes only to the destinations that do not have it yet.
		auditID = in.OccurrenceID
		activityID = uuid.NewSHA1(stableOccurrenceNamespace, []byte("activity\x00"+auditID)).String()
		if !in.OccurredAt.IsZero() {
			timestamp = in.OccurredAt.UTC()
		}
		var err error
		if spooled, err = l.spooledChange(ctx, in); err != nil {
			return err
		}
		if spooled.lookupErr != nil {
			localErr = spooled.lookupErr
		}
		if spooled.row != nil || localErr != nil {
			ctx = observability.WithSkipLocalWrite(ctx)
		}
		ctx = withSpooledChange(spooled.context(ctx), spooled)
		delivery := in.RemoteDelivery
		if delivery == nil {
			delivery = observability.NewRemoteDelivery()
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
	spooled.pinEvent(&auditEv)
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
		return l.occurrenceDurable(ctx, in.OccurrenceID, localErr)
	}
	if spooled != nil {
		return fmt.Errorf("audit: no generated v8 family records spooled activity action %q", action)
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
		return nil
	}
	return fmt.Errorf("audit: no generated v8 family handled activity action %q", action)
}

// spooledChange reads what an offer of a spooled occurrence needs: its pin
// and the stored row. A pin that does not read is an error (no sink gets
// the offer). A store that cannot say whether it holds the row is not, for
// a pinned change and for a change's first offer: the offer skips the
// store (lookupErr) and still goes to the remote destinations. A change
// without a pin that an earlier offer may have sent (not its FirstOffer) is
// an error while the store cannot answer: its row may hold the record that
// offer sent, so no sink gets another record under its id. A row whose pin
// is gone pins the record the row holds: its provenance and the digest
// stored with it. A row without a digest cannot say which record it holds,
// so its change is not offered again.
func (l *Logger) spooledChange(ctx context.Context, in ActivityInput) (*spooledChange, error) {
	if in.Pins == nil {
		return nil, fmt.Errorf("audit: spooled occurrence %s has no record pins", in.OccurrenceID)
	}
	change := &spooledChange{pins: in.Pins, key: in.PinKey, id: in.OccurrenceID}
	var err error
	if change.pin, change.pinned, err = in.Pins.load(in.PinKey); err != nil {
		return nil, err
	}
	row, stored, lookupErr := l.store.storedChangeRow(ctx, in.OccurrenceID)
	switch {
	case lookupErr != nil:
		if !change.pinned && (in.ConfigChange == nil || !in.ConfigChange.FirstOffer) {
			return nil, fmt.Errorf("audit: change %s has no record pin and the audit store cannot say whether it holds "+
				"its record, so it is offered once the store answers: %w", in.PinKey, lookupErr)
		}
		change.lookupErr = lookupErr
	case stored:
		change.row = &row
		if !change.pinned {
			if change.pin, err = row.pin(); err != nil {
				return nil, err
			}
			change.pinned, change.fromRow = true, true
		}
	}
	return change, nil
}

// occurrenceDurable is the audit store's confirmation of an occurrence with
// a stable id (occurrenceID; none for any other): its row, just written or
// found stored by an earlier process, survives a power loss. The pool
// commits with synchronous=NORMAL, which a power loss can take back, so the
// store is flushed before its producer may count the row as stored. An
// offer the store could not answer (localErr) is not confirmed.
func (l *Logger) occurrenceDurable(ctx context.Context, occurrenceID string, localErr error) error {
	if occurrenceID == "" {
		return nil
	}
	if localErr != nil {
		return localErr
	}
	return l.store.SyncCommittedWrites(ctx)
}
