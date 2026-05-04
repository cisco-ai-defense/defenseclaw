// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import "strings"

// Action is the v7 curated registry of every audit-event `action`
// string emitted anywhere in DefenseClaw. Mirrors
// cli/defenseclaw/audit_actions.py (codegen'd) and drives
// schemas/audit-event.json's `action` enum.
//
// Rules:
//   - NEVER use a raw string literal at an audit.LogEvent call site.
//     Import this registry and use the typed constant.
//   - Adding a new action is a minor schema bump: append the
//     constant here, regenerate the schema (make check-schemas),
//     regenerate Python parity (make check-audit-actions).
//   - Removing or renaming a constant is a breaking change: bump
//     version.SchemaVersion and announce to downstream.
type Action string

const (
	// Lifecycle
	ActionInit  Action = "init"
	ActionStop  Action = "stop"
	ActionReady Action = "ready"

	// Scan pipeline
	ActionScan        Action = "scan"
	ActionScanStart   Action = "scan-start"
	ActionRescan      Action = "rescan"
	ActionRescanStart Action = "rescan-start"

	// Admission gate
	ActionBlock Action = "block"
	ActionAllow Action = "allow"
	ActionWarn  Action = "warn"

	// Quarantine / runtime enforcement
	ActionQuarantine Action = "quarantine"
	ActionRestore    Action = "restore"
	ActionDisable    Action = "disable"
	ActionEnable     Action = "enable"

	// Deploy / drift
	ActionDeploy Action = "deploy"
	ActionDrift  Action = "drift"

	// Network egress
	ActionNetworkEgressBlocked Action = "network-egress-blocked"
	ActionNetworkEgressAllowed Action = "network-egress-allowed"

	// Guardrail
	ActionGuardrailBlock Action = "guardrail-block"
	ActionGuardrailWarn  Action = "guardrail-warn"
	ActionGuardrailAllow Action = "guardrail-allow"

	// Approval flow
	ActionApprovalRequest Action = "approval-request"
	ActionApprovalGranted Action = "approval-granted"
	ActionApprovalDenied  Action = "approval-denied"

	// Tool runtime
	ActionToolCall   Action = "tool-call"
	ActionToolResult Action = "tool-result"

	// Operator mutations (v7 Activity)
	ActionConfigUpdate  Action = "config-update"
	ActionPolicyUpdate  Action = "policy-update"
	ActionPolicyReload  Action = "policy-reload"
	ActionAction        Action = "action" // generic action mutation (block/allow list update)
	ActionAckAlerts     Action = "acknowledge-alerts"
	ActionDismissAlerts Action = "dismiss-alerts"

	// Webhook / notifier
	ActionWebhookDelivered Action = "webhook-delivered"
	ActionWebhookFailed    Action = "webhook-failed"

	// Sink / telemetry health
	ActionSinkFailure  Action = "sink-failure"
	ActionSinkRestored Action = "sink-restored"

	// Runtime alert (LogAlert). Emitted when a subsystem flips a
	// signal the operator needs to see right away; the severity
	// field on the audit row carries WARN / HIGH / CRITICAL.
	ActionAlert Action = "alert"

	// Connector observability ingress (native OTLP and hook telemetry).
	// The OTLP-HTTP receiver in
	// internal/gateway/otel_ingest.go persists one row per
	// inbound batch so SIEM rollups can answer "is the connector
	// reporting?" without scanning Loki/Tempo. We split by signal
	// (logs/metrics/traces) plus a dedicated `malformed` action so
	// schema-drift events stay visible without poisoning the
	// happy-path counters. Severity defaults to INFO; malformed
	// payloads upgrade to WARN.
	ActionOTelIngestLogs      Action = "otel.ingest.logs"
	ActionOTelIngestMetrics   Action = "otel.ingest.metrics"
	ActionOTelIngestTraces    Action = "otel.ingest.traces"
	ActionOTelIngestMalformed Action = "otel.ingest.malformed"

	// Codex notify webhook (agent-turn-complete et al.). The
	// notify-bridge.sh shim installed by the codex connector POSTs
	// codex's raw JSON arg to /api/v1/codex/notify after every
	// turn (https://developers.openai.com/codex/config-advanced).
	// We persist:
	//   - codex.notify.<type>  for known/sanitized type values
	//   - codex.notify         when the body has no `type` field
	//   - codex.notify.malformed when JSON parse fails
	// `agent-turn-complete` is by far the most common type today;
	// it is registered explicitly so dashboards have a stable
	// label without reading sanitization output.
	ActionCodexNotify                  Action = "codex.notify"
	ActionCodexNotifyAgentTurnComplete Action = "codex.notify.agent-turn-complete"
	ActionCodexNotifyMalformed         Action = "codex.notify.malformed"
)

// AllActions returns every registered audit action. Used by
// scripts/check_audit_actions.py (Go↔Python parity gate) and by
// schemas/audit-event.json codegen.
func AllActions() []Action {
	return []Action{
		ActionInit,
		ActionStop,
		ActionReady,
		ActionScan,
		ActionScanStart,
		ActionRescan,
		ActionRescanStart,
		ActionBlock,
		ActionAllow,
		ActionWarn,
		ActionQuarantine,
		ActionRestore,
		ActionDisable,
		ActionEnable,
		ActionDeploy,
		ActionDrift,
		ActionNetworkEgressBlocked,
		ActionNetworkEgressAllowed,
		ActionGuardrailBlock,
		ActionGuardrailWarn,
		ActionGuardrailAllow,
		ActionApprovalRequest,
		ActionApprovalGranted,
		ActionApprovalDenied,
		ActionToolCall,
		ActionToolResult,
		ActionConfigUpdate,
		ActionPolicyUpdate,
		ActionPolicyReload,
		ActionAction,
		ActionAckAlerts,
		ActionDismissAlerts,
		ActionWebhookDelivered,
		ActionWebhookFailed,
		ActionSinkFailure,
		ActionSinkRestored,
		ActionAlert,
		ActionOTelIngestLogs,
		ActionOTelIngestMetrics,
		ActionOTelIngestTraces,
		ActionOTelIngestMalformed,
		ActionCodexNotify,
		ActionCodexNotifyAgentTurnComplete,
		ActionCodexNotifyMalformed,
	}
}

// IsKnownActionPrefix reports whether s belongs to a curated
// dynamic-suffix family (today: codex.notify.<sanitized-type>).
// Callers persisting events with operator-derived suffixes — e.g.
// the codex notify handler that builds "codex.notify.<type>"
// from the inbound payload — should accept the value if either
// IsKnownAction(s) or IsKnownActionPrefix(s) returns true.
//
// The dynamic suffix is bounded by sanitizeNotifyType (max 64
// chars, [a-z0-9._-] only) so the Action column does not become
// a high-cardinality field on accident.
func IsKnownActionPrefix(s string) bool {
	const codexNotifyPrefix = "codex.notify."
	if !strings.HasPrefix(s, codexNotifyPrefix) {
		return false
	}
	// Suffix must be non-empty and within sanitizeNotifyType's
	// allow-list. Re-deriving the rule here keeps audit/actions.go
	// independent of internal/gateway and prevents the validator
	// from drifting if the notify schema is extended.
	suffix := s[len(codexNotifyPrefix):]
	if suffix == "" || len(suffix) > 64 {
		return false
	}
	for i := 0; i < len(suffix); i++ {
		c := suffix[i]
		switch {
		case c >= 'a' && c <= 'z',
			c >= '0' && c <= '9',
			c == '-' || c == '_' || c == '.':
			continue
		default:
			return false
		}
	}
	return true
}

// IsKnownAction reports whether s is a registered action. Callers
// that accept audit actions from untrusted surfaces (CLI args, HTTP
// payloads, plugin RPC) should reject unknown values rather than
// silently passing them through to SQLite.
//
// For dynamic suffix families (codex.notify.<sanitized-type>), use
// IsKnownActionPrefix in addition to (or instead of) this check.
func IsKnownAction(s string) bool {
	for _, a := range AllActions() {
		if string(a) == s {
			return true
		}
	}
	return false
}
