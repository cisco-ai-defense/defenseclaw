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
//   - We skip "guardrail-verdict" actions because the guardrail hot
//     path already emits a Verdict event via emitVerdict. Bridging
//     them would double-count in the JSONL stream.
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
func (b *auditBridge) EmitAudit(e audit.Event) {
	if b == nil || b.writer == nil {
		return
	}
	if skipBridgeAction(e.Action) {
		return
	}

	ev := gatewaylog.Event{
		Timestamp: e.Timestamp,
		EventType: gatewaylog.EventLifecycle,
		Severity:  normalizeAuditSeverity(e.Severity),
		RunID:     e.RunID,
		RequestID: e.RequestID,
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
// those here would produce duplicate rows in gateway.jsonl.
func skipBridgeAction(action string) bool {
	switch action {
	case "guardrail-verdict":
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

// transitionForAction extracts the transition verb. We prefer the
// LifecyclePayload.Transition vocabulary (start | stop | ready |
// degraded | restored | completed) but tolerate arbitrary verbs so
// new audit actions don't require schema changes.
func transitionForAction(action string) string {
	switch action {
	case "sidecar-start", "watch-start":
		return "start"
	case "sidecar-stop", "watch-stop":
		return "stop"
	case "sidecar-connected", "gateway-ready":
		return "ready"
	case "sidecar-disconnected":
		return "degraded"
	case "scan":
		return "completed"
	}
	// Fallback: use the raw action verb so the field is never empty.
	// Action names are controlled by internal callers (no user input
	// reaches here), so this is safe to forward verbatim.
	return action
}

// auditDetailsToMap packages the audit Event's free-form fields into
// the Lifecycle details bag. We keep the redaction invariant intact:
// every field originated from audit.sanitizeEvent, so no raw user
// content reaches here.
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
	if e.TraceID != "" {
		out["trace_id"] = e.TraceID
	}
	if e.RequestID != "" {
		out["request_id"] = e.RequestID
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
