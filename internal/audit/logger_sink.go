// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

func (l *Logger) sinkDeliveryHook(ctx context.Context, kind, sinkName string, err error, latencyMs float64) {
	if l == nil || l.store == nil {
		return
	}
	_, tel, _ := l.snapshot()
	prov := version.Current()
	now := time.Now().UTC()
	retryCount := 0
	if err != nil {
		statusCode := extractHTTPStatus(err)
		reason := sinkFailureReason(err)
		if tel != nil {
			tel.RecordSinkBatchFailed(ctx, sinkName, kind, statusCode, retryCount)
			tel.RecordSinkFailure(kind, sinkName, reason)
		}
		_ = l.store.InsertSinkHealth(SinkHealthInput{
			Timestamp:     now,
			SinkName:      sinkName,
			SinkKind:      kind,
			Outcome:       "failed",
			StatusCode:    statusCode,
			LatencyMs:     int64(latencyMs),
			BatchSize:     1,
			Error:         fmt.Sprintf("retry_count=%d | %v", retryCount, err),
			SchemaVersion: prov.SchemaVersion,
			ContentHash:   prov.ContentHash,
			Generation:    prov.Generation,
			BinaryVersion: prov.BinaryVersion,
		})
		l.emitSinkFailureAuditAndGateway(ctx, sinkName, kind, classifySinkFailureCode(err), err)
		return
	}
	if tel != nil {
		sc := http.StatusOK
		tel.RecordSinkBatchDelivered(ctx, sinkName, kind, sc, retryCount, latencyMs)
	}
	_ = l.store.InsertSinkHealth(SinkHealthInput{
		Timestamp:     now,
		SinkName:      sinkName,
		SinkKind:      kind,
		Outcome:       "delivered",
		StatusCode:    http.StatusOK,
		LatencyMs:     int64(latencyMs),
		BatchSize:     1,
		SchemaVersion: prov.SchemaVersion,
		ContentHash:   prov.ContentHash,
		Generation:    prov.Generation,
		BinaryVersion: prov.BinaryVersion,
	})
}

func classifySinkFailureCode(err error) gatewaylog.ErrorCode {
	if err == nil {
		return ""
	}
	s := err.Error()
	if strings.Contains(s, "backlog") || strings.Contains(s, "dropping") || strings.Contains(s, "cap ") {
		return gatewaylog.ErrCodeSinkQueueFull
	}
	return gatewaylog.ErrCodeSinkDeliveryFailed
}

func extractHTTPStatus(err error) int {
	if err == nil {
		return 0
	}
	s := err.Error()
	// "HEC returned 503" / "returned 503"
	for _, prefix := range []string{"returned ", "HTTP ", "status "} {
		if i := strings.Index(s, prefix); i >= 0 {
			var code int
			if n, _ := fmt.Sscanf(s[i+len(prefix):], "%d", &code); n == 1 && code >= 100 && code < 600 {
				return code
			}
		}
	}
	return 0
}

func sinkFailureReason(err error) string {
	if err == nil {
		return "unknown"
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "timeout") || strings.Contains(s, "deadline"):
		return "timeout"
	case strings.Contains(s, "backlog") || strings.Contains(s, "dropping"):
		return "queue_full"
	case strings.Contains(s, "encode") || strings.Contains(s, "marshal"):
		return "serialize_error"
	default:
		return "http_error"
	}
}

func (l *Logger) emitSinkFailureAuditAndGateway(ctx context.Context, sinkName, kind string, code gatewaylog.ErrorCode, err error) {
	_, otel, emitter := l.snapshot()
	ev := gatewaylog.Event{
		Timestamp: time.Now().UTC(),
		EventType: gatewaylog.EventError,
		Severity:  gatewaylog.SeverityHigh,
		RunID:     currentRunID(),
		Error: &gatewaylog.ErrorPayload{
			Subsystem: string(gatewaylog.SubsystemSink),
			Code:      string(code),
			Message:   fmt.Sprintf("audit sink %q (%s) delivery failed", sinkName, kind),
			Cause:     err.Error(),
		},
	}
	ev.StampProvenance()
	if otel != nil {
		otel.RecordGatewayEvent(ev)
	}
	l.emitGatewaySnapshot(emitter, ev)

	ae := Event{
		ID:        uuid.New().String(),
		Timestamp: time.Now().UTC(),
		Action:    string(ActionSinkFailure),
		Target:    sinkName,
		Actor:     "defenseclaw",
		Details:   fmt.Sprintf(`{"sink_kind":%q,"sink":%q,"code":%q}`, kind, sinkName, code),
		Severity:  "HIGH",
		RunID:     currentRunID(),
	}
	ae = sanitizeEvent(ae)
	if err := l.store.LogEvent(ae); err != nil {
		if otel != nil {
			otel.RecordAuditDBError(ctx, "insert_sink_failure_audit")
		}
		return
	}
	if otel != nil {
		otel.RecordAuditEvent(ctx, ae.Action, ae.Severity)
	}
	l.emitStructuredSnapshot(emitter, ae)
}

func (l *Logger) onCircuitTripActivity(kind, sinkName string) {
	if l == nil {
		return
	}
	_ = l.LogActivity(ActivityInput{
		Actor:          "defenseclaw",
		Action:         ActionSinkFailure,
		TargetType:     "sink",
		TargetID:       sinkName,
		Reason:         "consecutive forward failures reached threshold",
		Before:         map[string]any{"circuit": "closed", "sink_kind": kind},
		After:          map[string]any{"circuit": "open", "sink_kind": kind},
		Severity:       "HIGH",
		SkipSinkFanout: true,
	})
}

func (l *Logger) onCircuitRecoverActivity(kind, sinkName string) {
	if l == nil {
		return
	}
	_ = l.LogActivity(ActivityInput{
		Actor:          "defenseclaw",
		Action:         ActionSinkRestored,
		TargetType:     "sink",
		TargetID:       sinkName,
		Reason:         "sink delivery succeeded after open circuit",
		Before:         map[string]any{"circuit": "open", "sink_kind": kind},
		After:          map[string]any{"circuit": "closed", "sink_kind": kind},
		Severity:       "INFO",
		SkipSinkFanout: true,
	})
}
