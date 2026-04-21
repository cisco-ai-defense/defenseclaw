// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
)

// auditBridge translates sanitized audit.Event records into structured
// gatewaylog.Event emissions. It lets every scan, watcher transition,
// and enforcement action flow into gateway.jsonl alongside guardrail
// verdicts — giving operators a single, correlated observability
// stream instead of three half-populated ones (audit SQLite, OTel,
// and gateway.jsonl).
//
// Design notes:
//   - The bridge is intentionally stateless. audit.Logger already
//     redacts Details at the sanitizer choke point before we see the
//     event, so the bridge can forward text verbatim without
//     re-running PII detection.
//   - We skip actions that already have a dedicated structured
//     emission on the gateway hot path (guardrail verdicts and
//     llm-judge responses): the proxy calls emitVerdict/emitJudge
//     *and* persists a matching audit event for SQLite/OTLP/Splunk
//     fan-out, so bridging the audit twin into JSONL would produce
//     duplicate rows in gateway.jsonl. The dedicated structured
//     emission wins and this bridge stays out of its way.
//   - All other actions surface as Lifecycle events — the schema's
//     catch-all for non-verdict state transitions. The subsystem is
//     inferred from the action prefix so TUI/sinks can filter on it.
type auditBridge struct {
	writer *gatewaylog.Writer
}

func newAuditBridge(w *gatewaylog.Writer) *auditBridge {
	if w == nil {
		return nil
	}
	return &auditBridge{writer: w}
}

// EmitAudit is invoked by audit.Logger on every successful persistence
// of an Event. It never blocks the caller for longer than a single
// Emit call — the underlying Writer fans out to disk + stderr
// synchronously but OTel/sink callbacks run outside its mutex.
// EmitGatewayEvent writes a pre-built gatewaylog event (v7 activity,
// alerts, errors) without translating from audit.Event.
func (b *auditBridge) EmitGatewayEvent(ev gatewaylog.Event) {
	if b == nil || b.writer == nil {
		return
	}
	b.writer.Emit(ev)
}

func (b *auditBridge) EmitAudit(e audit.Event) {
	if b == nil || b.writer == nil {
		return
	}
	if skipBridgeAction(e.Action) {
		return
	}
	// v7: LogActivity mirrors a native EventActivity emission; skip the
	// lifecycle translation so gateway.jsonl stays single-sourced.
	if strings.Contains(e.Details, `"activity_id"`) {
		return
	}

	ev := gatewaylog.Event{
		Timestamp:         e.Timestamp,
		EventType:         gatewaylog.EventLifecycle,
		Severity:          normalizeAuditSeverity(e.Severity),
		RunID:             e.RunID,
		RequestID:         e.RequestID,
		SessionID:         e.SessionID,
		TraceID:           e.TraceID,
		AgentID:           e.AgentID,
		AgentName:         e.AgentName,
		AgentInstanceID:   e.AgentInstanceID,
		SidecarInstanceID: e.SidecarInstanceID,
		PolicyID:          e.PolicyID,
		DestinationApp:    e.DestinationApp,
		ToolName:          e.ToolName,
		ToolID:            e.ToolID,
		Lifecycle: &gatewaylog.LifecyclePayload{
			Subsystem:  subsystemForAction(e.Action),
			Transition: transitionForAction(e.Action),
			Details:    auditDetailsToMap(e),
		},
	}
	b.writer.Emit(ev)
}

// skipBridgeAction returns true for audit actions whose structured
// event is already emitted directly by the gateway hot path. Bridging
// those here would produce duplicate rows in gateway.jsonl (one from
// the native emit* call, one from this bridge translating the audit
// twin). The set is intentionally tiny and explicit — adding a new
// native emitter means auditing this switch too.
func skipBridgeAction(action string) bool {
	switch action {
	case "guardrail-verdict",
		// emitJudge already writes an EventJudge row; the matching
		// "llm-judge-response" audit event exists for SQLite/Splunk
		// fan-out (see sidecar.go judgePersistor) and must not be
		// re-translated into a Lifecycle JSONL row.
		"llm-judge-response",
		// LogScan already emits a native EventScan (and EventScanFinding
		// per finding) via scanner.EmitScanResult; the "scan" audit twin
		// exists for SQLite/Splunk fan-out and must not be re-translated
		// into a Lifecycle JSONL row.
		string(audit.ActionScan),
		// LogAlert already emits a native EventLifecycle with
		// transition="alert"; the "alert" audit twin exists for
		// SQLite/Splunk fan-out and must not be re-translated again.
		string(audit.ActionAlert):
		return true
	}
	return false
}

// subsystemForAction maps an audit Action into the gatewaylog
// Subsystem vocabulary (gateway | watcher | sinks | telemetry | api |
// scanner | enforcement). Unknown actions fall back to "gateway" so
// the field is never empty — sinks index on it.
func subsystemForAction(action string) string {
	switch {
	case action == "scan":
		return "scanner"
	case strings.HasPrefix(action, "watcher-") || action == "watch-start" || action == "watch-stop":
		return "watcher"
	case strings.HasPrefix(action, "sidecar-") || action == "gateway-ready":
		return "gateway"
	case strings.HasPrefix(action, "api-"):
		return "api"
	case strings.HasPrefix(action, "sink-") || strings.HasPrefix(action, "splunk-"):
		return "sinks"
	case strings.HasPrefix(action, "otel-") || strings.HasPrefix(action, "telemetry-"):
		return "telemetry"
	case strings.HasPrefix(action, "skill-") ||
		strings.HasPrefix(action, "mcp-") ||
		strings.HasPrefix(action, "install-") ||
		strings.HasPrefix(action, "block-") ||
		strings.HasPrefix(action, "allow-") ||
		strings.HasPrefix(action, "quarantine-") ||
		action == "block" || action == "allow" || action == "quarantine":
		return "enforcement"
	default:
		return "gateway"
	}
}

// transitionForAction maps an audit Action onto the canonical
// LifecyclePayload.Transition vocabulary (start | stop | ready |
// degraded | restored | alert | completed). Every audit row that
// reaches the bridge represents a completed internal action, so
// "completed" is the safe catch-all. This keeps gateway.jsonl
// schema-valid without requiring the enum to track every possible
// audit action verb.
func transitionForAction(action string) string {
	switch action {
	case "sidecar-start", "watch-start":
		return "start"
	case "sidecar-stop", "watch-stop":
		return "stop"
	case "sidecar-connected", "gateway-ready":
		return "ready"
	case "sidecar-disconnected", string(audit.ActionSinkFailure):
		return "degraded"
	case string(audit.ActionSinkRestored):
		return "restored"
	}
	// Catch-all: every other audit action represents an internal
	// operation that finished (install-blocked, policy-update,
	// rescan-start, approval-granted, ...). Mapping them all to
	// "completed" keeps the field within the schema enum while still
	// carrying the originating action in LifecyclePayload.Details.
	return "completed"
}

// auditDetailsToMap packages the audit Event's free-form fields into
// the Lifecycle details bag. We keep the redaction invariant intact:
// every field originated from audit.sanitizeEvent, so no raw user
// content reaches here.
//
// Fields already surfaced by the gatewaylog.Event envelope (RequestID,
// RunID, SessionID, TraceID, AgentName, AgentInstanceID, PolicyID,
// DestinationApp, ToolName, ToolID, Severity, Timestamp) are
// deliberately *not* copied into the details map — they would drift
// against the canonical envelope copy if schema normalisation
// diverged, and downstream consumers already key on the envelope.
// audit_id and action stay so operators can pivot from a JSONL row
// back to the SQLite row that produced it.
func auditDetailsToMap(e audit.Event) map[string]string {
	out := map[string]string{}
	if e.Target != "" {
		out["target"] = e.Target
	}
	if e.Actor != "" {
		out["actor"] = e.Actor
	}
	if e.Details != "" {
		out["details"] = e.Details
	}
	if e.ID != "" {
		out["audit_id"] = e.ID
	}
	if e.Action != "" {
		out["action"] = e.Action
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// normalizeAuditSeverity coerces audit severities (INFO / LOW / MEDIUM
// / HIGH / CRITICAL, case-insensitive) into the canonical
// gatewaylog.Severity vocabulary. Empty values default to INFO so the
// field is never missing on the wire.
func normalizeAuditSeverity(s string) gatewaylog.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return gatewaylog.SeverityCritical
	case "HIGH":
		return gatewaylog.SeverityHigh
	case "MEDIUM":
		return gatewaylog.SeverityMedium
	case "LOW":
		return gatewaylog.SeverityLow
	case "", "INFO":
		return gatewaylog.SeverityInfo
	default:
		return gatewaylog.SeverityInfo
	}
}
