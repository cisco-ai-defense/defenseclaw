// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/defenseclaw/defenseclaw/internal/audit/sinks"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

func parseGatewaySeverity(s string) gatewaylog.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return gatewaylog.SeverityCritical
	case "HIGH":
		return gatewaylog.SeverityHigh
	case "MEDIUM", "MED":
		return gatewaylog.SeverityMedium
	case "LOW", "WARN":
		return gatewaylog.SeverityLow
	default:
		return gatewaylog.SeverityInfo
	}
}

func redactMapShallow(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		switch t := v.(type) {
		case string:
			out[k] = redaction.ForSinkString(t)
		case map[string]any:
			out[k] = redactMapShallow(t)
		default:
			b, _ := json.Marshal(v)
			out[k] = redaction.ForSinkString(string(b))
		}
	}
	return out
}

func activityDiffToGateway(in []ActivityDiffEntry) []gatewaylog.DiffEntry {
	out := make([]gatewaylog.DiffEntry, 0, len(in))
	for _, d := range in {
		out = append(out, gatewaylog.DiffEntry{
			Path:   d.Path,
			Op:     d.Op,
			Before: d.Before,
			After:  d.After,
		})
	}
	return out
}

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
	prov := version.Current()

	beforeJSON, _ := json.Marshal(in.Before)
	afterJSON, _ := json.Marshal(in.After)
	diffJSON, _ := json.Marshal(in.Diff)

	row := ActivityEventRow{
		ID:                activityID,
		Timestamp:         time.Now().UTC(),
		Actor:             actor,
		Action:            action,
		TargetType:        targetType,
		TargetID:          targetID,
		Reason:            in.Reason,
		BeforeJSON:        string(beforeJSON),
		AfterJSON:         string(afterJSON),
		DiffJSON:          string(diffJSON),
		VersionFrom:       in.VersionFrom,
		VersionTo:         in.VersionTo,
		RequestID:         in.RequestID,
		TraceID:           in.TraceID,
		RunID:             in.RunID,
		SchemaVersion:     prov.SchemaVersion,
		ContentHash:       prov.ContentHash,
		Generation:        prov.Generation,
		BinaryVersion:     prov.BinaryVersion,
		SidecarInstanceID: ProcessAgentInstanceID(),
	}
	if row.RunID == "" {
		row.RunID = currentRunID()
	}

	if err := l.store.InsertActivityEvent(row); err != nil {
		_, otel, _ := l.snapshot()
		if otel != nil {
			otel.RecordAuditDBError(context.Background(), "insert_activity_event")
		}
		return fmt.Errorf("audit: activity row: %w", err)
	}

	summary := map[string]any{
		"activity_id":  activityID,
		"actor":        actor,
		"action":       action,
		"target_type":  targetType,
		"target_id":    targetID,
		"reason":       redaction.ForSinkReason(in.Reason),
		"before":       redactMapShallow(in.Before),
		"after":        redactMapShallow(in.After),
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
		RunID:             row.RunID,
		RequestID:         in.RequestID,
		TraceID:           in.TraceID,
		SchemaVersion:     prov.SchemaVersion,
		ContentHash:       prov.ContentHash,
		Generation:        prov.Generation,
		BinaryVersion:     prov.BinaryVersion,
		SidecarInstanceID: ProcessAgentInstanceID(),
	}
	auditEv = sanitizeEvent(auditEv)
	if err := l.store.LogEvent(auditEv); err != nil {
		_, otel, _ := l.snapshot()
		if otel != nil {
			otel.RecordAuditDBError(context.Background(), "insert_activity_audit")
		}
		return err
	}

	sinksMgr, otel, structured := l.snapshot()
	if otel != nil {
		otel.RecordAuditEvent(context.Background(), auditEv.Action, auditEv.Severity, telemetry.MetricEnvelope{
			PolicyID:          auditEv.PolicyID,
			DestinationApp:    auditEv.DestinationApp,
			AgentName:         auditEv.AgentName,
			AgentInstanceID:   auditEv.AgentInstanceID,
			SidecarInstanceID: auditEv.SidecarInstanceID,
		})
		otel.RecordActivityTotal(context.Background(), action, targetType, actor, len(in.Diff))
	}
	l.emitStructuredSnapshot(structured, auditEv)

	gwActivity := &gatewaylog.ActivityPayload{
		Actor:       actor,
		Action:      action,
		TargetType:  targetType,
		TargetID:    targetID,
		Reason:      in.Reason,
		Before:      in.Before,
		After:       in.After,
		Diff:        activityDiffToGateway(in.Diff),
		VersionFrom: in.VersionFrom,
		VersionTo:   in.VersionTo,
	}
	gwEv := gatewaylog.Event{
		Timestamp: time.Now().UTC(),
		EventType: gatewaylog.EventActivity,
		Severity:  parseGatewaySeverity(severity),
		RunID:     row.RunID,
		RequestID: in.RequestID,
		TraceID:   in.TraceID,
		Activity:  gwActivity,
	}
	stampGatewayEnvelope(&gwEv)
	if otel != nil {
		otel.RecordGatewayEvent(gwEv)
	}
	l.emitGatewaySnapshot(structured, gwEv)

	if !in.SkipSinkFanout {
		se := sinks.Event{
			ID:                auditID,
			Timestamp:         auditEv.Timestamp,
			Action:            action,
			Target:            auditEv.Target,
			Actor:             actor,
			Details:           string(summaryBlob),
			Severity:          severity,
			RunID:             row.RunID,
			TraceID:           in.TraceID,
			RequestID:         in.RequestID,
			SidecarInstanceID: ProcessAgentInstanceID(),
			Structured: map[string]any{
				"defenseclaw_event": "activity",
				"activity_id":       activityID,
				"actor":             actor,
				"action":            action,
				"target_type":       targetType,
				"target_id":         targetID,
			},
		}
		if sinksMgr != nil {
			fwdCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = sinksMgr.Forward(fwdCtx, se)
		}
	}
	return nil
}
