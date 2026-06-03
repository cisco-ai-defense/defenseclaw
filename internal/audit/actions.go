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
	ActionConnectorHook       Action = "connector-hook"
	// ActionConnectorHookSynthetic identifies a hook audit row that
	// was synthesized by the gateway from a vendor-specific
	// telemetry endpoint (today: codex's /api/v1/codex/notify
	// agent-turn-complete callback). The canonical vendor row
	// (e.g. codex.notify.agent-turn-complete) is always written
	// too, so downstream SIEM rules that count "1 codex.notify in
	// → 1 row out" keep working; this action lets new dashboards
	// reason about the synthesized event without disturbing them.
	ActionConnectorHookSynthetic Action = "connector-hook-synthetic"
	ActionAssetPolicy            Action = "asset-policy"

	// Connector hook self-heal. The hook config guard
	// (internal/gateway/hook_config_guard.go) watches each active
	// connector's agent config file (e.g. ~/.cursor/hooks.json,
	// ~/.claude/settings.json, ~/.codex/config.toml) and re-installs
	// the DefenseClaw hook block when a user removes it while the
	// gateway is running. Tampered records the detection; Repaired
	// records the successful re-install.
	ActionConnectorHookTampered Action = "connector-hook-tampered"
	ActionConnectorHookRepaired Action = "connector-hook-repaired"

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

	// Sidecar lifecycle and bootstrap instrumentation. These actions
	// describe gateway-side startup, shutdown, WebSocket connectivity,
	// and watcher decisions that are proxied through the sidecar.
	ActionSidecarStart                Action = "sidecar-start"
	ActionSidecarStop                 Action = "sidecar-stop"
	ActionSidecarConnected            Action = "sidecar-connected"
	ActionSidecarDisconnected         Action = "sidecar-disconnected"
	ActionSidecarWatcherVerdict       Action = "sidecar-watcher-verdict"
	ActionSidecarWatcherDisable       Action = "sidecar-watcher-disable"
	ActionSidecarWatcherDisablePlugin Action = "sidecar-watcher-disable-plugin"
	ActionSidecarWatcherBlockMCP      Action = "sidecar-watcher-block-mcp"
	ActionBootstrap                   Action = "bootstrap"

	// Watcher lifecycle instrumentation. These actions describe the
	// filesystem watcher and the install gate outcomes for skills,
	// plugins, and MCP servers.
	ActionWatchStart                Action = "watch-start"
	ActionWatchStop                 Action = "watch-stop"
	ActionWatcherBlock              Action = "watcher-block"
	ActionInstallDetected           Action = "install-detected"
	ActionInstallRejected           Action = "install-rejected"
	ActionInstallAllowed            Action = "install-allowed"
	ActionInstallAllowedSkipEnforce Action = "install-allowed-skip-enforce"
	ActionInstallClean              Action = "install-clean"
	ActionInstallWarning            Action = "install-warning"
	ActionInstallScanError          Action = "install-scan-error"
	ActionInstallEnforced           Action = "install-enforced"
	ActionInstallBlocked            Action = "install-blocked"
	ActionInstallDep                Action = "install-dep"

	// Gateway session router instrumentation. These actions track
	// stream/session/router health, tool calls/results, approval flow,
	// and runtime prompt or tool alerts observed by the gateway.
	ActionGatewayReady                Action = "gateway-ready"
	ActionGatewaySessionMessage       Action = "gateway-session-message"
	ActionGatewaySessionPromptAlert   Action = "gateway-session-prompt-alert"
	ActionGatewaySessionError         Action = "gateway-session-error"
	ActionGatewayChatError            Action = "gateway-chat-error"
	ActionGatewayAgentStart           Action = "gateway-agent-start"
	ActionGatewayAgentEnd             Action = "gateway-agent-end"
	ActionGatewayAgentError           Action = "gateway-agent-error"
	ActionGatewayToolCall             Action = "gateway-tool-call"
	ActionGatewayToolCallBlocked      Action = "gateway-tool-call-blocked"
	ActionGatewayToolCallFlagged      Action = "gateway-tool-call-flagged"
	ActionGatewayToolCallJudgeFlagged Action = "gateway-tool-call-judge-flagged"
	ActionGatewayToolResult           Action = "gateway-tool-result"
	ActionGatewayApprovalRequested    Action = "gateway-approval-requested"
	ActionGatewayApprovalDenied       Action = "gateway-approval-denied"
	ActionGatewayApprovalGranted      Action = "gateway-approval-granted"
	ActionGatewayApprovalPending      Action = "gateway-approval-pending"
	ActionGatewayMultiTurnInjection   Action = "gateway-multi-turn-injection"
	ActionGatewayDown                 Action = "gateway-down"
	ActionGatewayRecovered            Action = "gateway-recovered"
	ActionGatewayDegraded             Action = "gateway-degraded"
	ActionToolResultPIIAlert          Action = "tool-result-pii-alert"

	// Gateway judge-bodies / judge-store sidecar lifecycle. These
	// actions track the optional judge-response body store and the
	// async judge-response persistence store as the gateway sidecar
	// opens them, falls back to audit.db, drains on shutdown, and
	// reports close failures.
	ActionGatewayJudgeBodiesReady        Action = "gateway.judge_bodies.ready"
	ActionGatewayJudgeBodiesFallback     Action = "gateway.judge_bodies.fallback"
	ActionGatewayJudgeBodiesCloseSkipped Action = "gateway.judge_bodies.close_skipped"
	ActionGatewayJudgeBodiesCloseError   Action = "gateway.judge_bodies.close_error"
	ActionGatewayJudgeStoreDrainTimeout  Action = "gateway.judge_store.drain_timeout"

	// Guardrail and inspect instrumentation. These actions describe
	// proxy health, verdict/inspection rows, OPA evaluation, guardrail
	// config changes, inspect-tool decisions, and judge summaries.
	ActionGuardrailStart              Action = "guardrail-start"
	ActionGuardrailHealthy            Action = "guardrail-healthy"
	ActionGuardrailVerdict            Action = "guardrail-verdict"
	ActionGuardrailInspection         Action = "guardrail-inspection"
	ActionGuardrailOPAInspection      Action = "guardrail-opa-inspection"
	ActionGuardrailOPAVerdict         Action = "guardrail-opa-verdict"
	ActionGuardrailConfigReload       Action = "guardrail-config-reload"
	ActionGuardrailDegraded           Action = "guardrail-degraded"
	ActionGuardrailLaunder            Action = "guardrail-launder"
	ActionGuardrailNotifyInject       Action = "guardrail-notify-inject"
	ActionGuardrailToolCallParseError Action = "guardrail-tool-call-parse-error"
	ActionGuardrailToolCallInspect    Action = "guardrail-tool-call-inspect"
	ActionGuardrailDisable            Action = "guardrail-disable"
	ActionGuardrailEnable             Action = "guardrail-enable"
	ActionGuardrailFailMode           Action = "guardrail-fail-mode"
	ActionLLMJudgeResponse            Action = "llm-judge-response"
	ActionInspectToolConfirm          Action = "inspect-tool-confirm"
	ActionInspectToolBlock            Action = "inspect-tool-block"
	ActionInspectToolAlert            Action = "inspect-tool-alert"
	ActionInspectToolAllow            Action = "inspect-tool-allow"
	ActionInspectReveal               Action = "inspect-reveal"

	// Setup, operator, API, and sink instrumentation. These actions
	// describe CLI setup/doctor/init/upgrade flows, REST API mutations,
	// sink/auth failures, and operator mutations for skills, plugins,
	// MCP servers, tools, policies, and registries.
	ActionAPIAuthFailure           Action = "api-auth-failure"
	ActionAPIConfigPatch           Action = "api-config-patch"
	ActionAPIEnforceAllow          Action = "api-enforce-allow"
	ActionAPIEnforceBlock          Action = "api-enforce-block"
	ActionAPIEnforceUnblock        Action = "api-enforce-unblock"
	ActionAPIMCPScan               Action = "api-mcp-scan"
	ActionAPIPluginDisable         Action = "api-plugin-disable"
	ActionAPIPluginEnable          Action = "api-plugin-enable"
	ActionAPIPluginScan            Action = "api-plugin-scan"
	ActionAPISkillDisable          Action = "api-skill-disable"
	ActionAPISkillEnable           Action = "api-skill-enable"
	ActionAPISkillFetch            Action = "api-skill-fetch"
	ActionAPISkillScan             Action = "api-skill-scan"
	ActionSinkFlushError           Action = "sink-flush-error"
	ActionSetupSkillScanner        Action = "setup-skill-scanner"
	ActionSetupMCPScanner          Action = "setup-mcp-scanner"
	ActionSetupGateway             Action = "setup-gateway"
	ActionSetupGuardrail           Action = "setup-guardrail"
	ActionSetupHookConnector       Action = "setup-hook-connector"
	ActionSetupConnectorMode       Action = "setup-connector-mode"
	ActionSetupRedactionToggle     Action = "setup-redaction-toggle"
	ActionSetupNotificationsToggle Action = "setup-notifications-toggle"
	ActionSetupNotificationsSet    Action = "setup-notifications-set"
	ActionSetupSplunk              Action = "setup-splunk"
	ActionSetupObservability       Action = "setup-observability"
	ActionSetupLocalObservability  Action = "setup-local-observability"
	ActionSetupWebhook             Action = "setup-webhook"
	ActionDoctor                   Action = "doctor"
	ActionUpgrade                  Action = "upgrade"
	ActionInitGateway              Action = "init-gateway"
	ActionInitGuardrail            Action = "init-guardrail"
	ActionInitNotificationsToggle  Action = "init-notifications-toggle"
	ActionInitSandbox              Action = "init-sandbox"
	ActionInitSidecar              Action = "init-sidecar"
	ActionPolicyCreate             Action = "policy-create"
	ActionPolicyActivate           Action = "policy-activate"
	ActionPolicyDelete             Action = "policy-delete"
	ActionRegistryAdd              Action = "registry-add"
	ActionRegistryEdit             Action = "registry-edit"
	ActionRegistryRemove           Action = "registry-remove"
	ActionScanEnforced             Action = "scan-enforced"
	ActionScanFinding              Action = "scan-finding"
	ActionDismissAlert             Action = "dismiss-alert"
	ActionSkillBlock               Action = "skill-block"
	ActionSkillUnblock             Action = "skill-unblock"
	ActionSkillAllow               Action = "skill-allow"
	ActionSkillDisable             Action = "skill-disable"
	ActionSkillEnable              Action = "skill-enable"
	ActionSkillQuarantine          Action = "skill-quarantine"
	ActionSkillRestore             Action = "skill-restore"
	ActionPluginInstall            Action = "plugin-install"
	ActionPluginRemove             Action = "plugin-remove"
	ActionPluginBlock              Action = "plugin-block"
	ActionPluginAllow              Action = "plugin-allow"
	ActionPluginDisable            Action = "plugin-disable"
	ActionPluginEnable             Action = "plugin-enable"
	ActionPluginQuarantine         Action = "plugin-quarantine"
	ActionPluginRestore            Action = "plugin-restore"
	ActionBlockMCP                 Action = "block-mcp"
	ActionAllowMCP                 Action = "allow-mcp"
	ActionMCPUnblock               Action = "mcp-unblock"
	ActionMCPSet                   Action = "mcp-set"
	ActionMCPSetBlocked            Action = "mcp-set-blocked"
	ActionMCPUnset                 Action = "mcp-unset"
	ActionToolBlock                Action = "tool-block"
	ActionToolAllow                Action = "tool-allow"
	ActionToolUnblock              Action = "tool-unblock"
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
		ActionConnectorHook,
		ActionConnectorHookSynthetic,
		ActionAssetPolicy,
		ActionConnectorHookTampered,
		ActionConnectorHookRepaired,
		ActionCodexNotify,
		ActionCodexNotifyAgentTurnComplete,
		ActionCodexNotifyMalformed,
		ActionSidecarStart,
		ActionSidecarStop,
		ActionSidecarConnected,
		ActionSidecarDisconnected,
		ActionSidecarWatcherVerdict,
		ActionSidecarWatcherDisable,
		ActionSidecarWatcherDisablePlugin,
		ActionSidecarWatcherBlockMCP,
		ActionBootstrap,
		ActionWatchStart,
		ActionWatchStop,
		ActionWatcherBlock,
		ActionInstallDetected,
		ActionInstallRejected,
		ActionInstallAllowed,
		ActionInstallAllowedSkipEnforce,
		ActionInstallClean,
		ActionInstallWarning,
		ActionInstallScanError,
		ActionInstallEnforced,
		ActionInstallBlocked,
		ActionInstallDep,
		ActionGatewayReady,
		ActionGatewaySessionMessage,
		ActionGatewaySessionPromptAlert,
		ActionGatewaySessionError,
		ActionGatewayChatError,
		ActionGatewayAgentStart,
		ActionGatewayAgentEnd,
		ActionGatewayAgentError,
		ActionGatewayToolCall,
		ActionGatewayToolCallBlocked,
		ActionGatewayToolCallFlagged,
		ActionGatewayToolCallJudgeFlagged,
		ActionGatewayToolResult,
		ActionGatewayApprovalRequested,
		ActionGatewayApprovalDenied,
		ActionGatewayApprovalGranted,
		ActionGatewayApprovalPending,
		ActionGatewayMultiTurnInjection,
		ActionGatewayDown,
		ActionGatewayRecovered,
		ActionGatewayDegraded,
		ActionToolResultPIIAlert,
		ActionGatewayJudgeBodiesReady,
		ActionGatewayJudgeBodiesFallback,
		ActionGatewayJudgeBodiesCloseSkipped,
		ActionGatewayJudgeBodiesCloseError,
		ActionGatewayJudgeStoreDrainTimeout,
		ActionGuardrailStart,
		ActionGuardrailHealthy,
		ActionGuardrailVerdict,
		ActionGuardrailInspection,
		ActionGuardrailOPAInspection,
		ActionGuardrailOPAVerdict,
		ActionGuardrailConfigReload,
		ActionGuardrailDegraded,
		ActionGuardrailLaunder,
		ActionGuardrailNotifyInject,
		ActionGuardrailToolCallParseError,
		ActionGuardrailToolCallInspect,
		ActionGuardrailDisable,
		ActionGuardrailEnable,
		ActionGuardrailFailMode,
		ActionLLMJudgeResponse,
		ActionInspectToolConfirm,
		ActionInspectToolBlock,
		ActionInspectToolAlert,
		ActionInspectToolAllow,
		ActionInspectReveal,
		ActionAPIAuthFailure,
		ActionAPIConfigPatch,
		ActionAPIEnforceAllow,
		ActionAPIEnforceBlock,
		ActionAPIEnforceUnblock,
		ActionAPIMCPScan,
		ActionAPIPluginDisable,
		ActionAPIPluginEnable,
		ActionAPIPluginScan,
		ActionAPISkillDisable,
		ActionAPISkillEnable,
		ActionAPISkillFetch,
		ActionAPISkillScan,
		ActionSinkFlushError,
		ActionSetupSkillScanner,
		ActionSetupMCPScanner,
		ActionSetupGateway,
		ActionSetupGuardrail,
		ActionSetupHookConnector,
		ActionSetupConnectorMode,
		ActionSetupRedactionToggle,
		ActionSetupNotificationsToggle,
		ActionSetupNotificationsSet,
		ActionSetupSplunk,
		ActionSetupObservability,
		ActionSetupLocalObservability,
		ActionSetupWebhook,
		ActionDoctor,
		ActionUpgrade,
		ActionInitGateway,
		ActionInitGuardrail,
		ActionInitNotificationsToggle,
		ActionInitSandbox,
		ActionInitSidecar,
		ActionPolicyCreate,
		ActionPolicyActivate,
		ActionPolicyDelete,
		ActionRegistryAdd,
		ActionRegistryEdit,
		ActionRegistryRemove,
		ActionScanEnforced,
		ActionScanFinding,
		ActionDismissAlert,
		ActionSkillBlock,
		ActionSkillUnblock,
		ActionSkillAllow,
		ActionSkillDisable,
		ActionSkillEnable,
		ActionSkillQuarantine,
		ActionSkillRestore,
		ActionPluginInstall,
		ActionPluginRemove,
		ActionPluginBlock,
		ActionPluginAllow,
		ActionPluginDisable,
		ActionPluginEnable,
		ActionPluginQuarantine,
		ActionPluginRestore,
		ActionBlockMCP,
		ActionAllowMCP,
		ActionMCPUnblock,
		ActionMCPSet,
		ActionMCPSetBlocked,
		ActionMCPUnset,
		ActionToolBlock,
		ActionToolAllow,
		ActionToolUnblock,
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
