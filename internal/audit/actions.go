// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

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
	}
}

// IsKnownAction reports whether s is a registered action. Callers
// that accept audit actions from untrusted surfaces (CLI args, HTTP
// payloads, plugin RPC) should reject unknown values rather than
// silently passing them through to SQLite.
func IsKnownAction(s string) bool {
	for _, a := range AllActions() {
		if string(a) == s {
			return true
		}
	}
	return false
}
