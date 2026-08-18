// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/defenseclaw/defenseclaw/internal/observability"
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

	activityID := uuid.New().String()
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

	auditID := uuid.New().String()
	// v7 clean break: AgentInstanceID is per-session (unset for
	// activity/mutation events that have no session anchor);
	// SidecarInstanceID carries the process UUID.
	auditEv := Event{
		ID:                auditID,
		Timestamp:         time.Now().UTC(),
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
	activityMetrics, metricErr := newActivityRuntimeV8GeneratedMetrics(
		auditEv, action, targetType, actor, len(in.Diff),
	)
	if metricErr != nil {
		return metricErr
	}
	evidence, evidenceErr := controlPlaneV8ActivityEvidence(in)
	if evidenceErr != nil {
		return evidenceErr
	}
	disposition, emitErr := l.emitControlPlaneV8WithEvidenceAndMetrics(
		context.Background(), auditEv, evidence, activityMetrics,
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
		return nil
	}
	disposition, emitErr = l.emitCompatibilityAuditV8(
		context.Background(), auditEv,
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
