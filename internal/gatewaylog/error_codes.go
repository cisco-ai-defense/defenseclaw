// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gatewaylog

// ErrorCode is the v7 standardized vocabulary for the `code` field on
// every EventError emission. The (Subsystem, Code) pair is stable and
// safe to alert on; adding a new code is a minor schema bump, removing
// or renaming one is breaking.
//
// The list is mirrored into:
//   - cli/defenseclaw/gateway_error_codes.py (codegen'd)
//   - schemas/scan-event.json / activity-event.json / audit-event.json
//     via the `code` enum
//   - scripts/check_error_codes.py (Go↔Python parity gate)
//
// Use the typed constant, never raw strings, to keep grep-ability high
// and catch typos at compile time.
type ErrorCode string

const (
	// Sink subsystem
	ErrCodeSinkDeliveryFailed ErrorCode = "SINK_DELIVERY_FAILED"
	ErrCodeSinkQueueFull      ErrorCode = "SINK_QUEUE_FULL"

	// Telemetry subsystem
	ErrCodeExportFailed ErrorCode = "EXPORT_FAILED"

	// Config subsystem
	ErrCodeConfigLoadFailed ErrorCode = "CONFIG_LOAD_FAILED"

	// Policy subsystem
	ErrCodePolicyLoadFailed ErrorCode = "POLICY_LOAD_FAILED"

	// Auth subsystem
	ErrCodeAuthInvalidToken  ErrorCode = "AUTH_INVALID_TOKEN"
	ErrCodeAuthMissingToken  ErrorCode = "AUTH_MISSING_TOKEN"
	ErrCodeAuthCSRFMismatch  ErrorCode = "AUTH_CSRF_MISMATCH"
	ErrCodeAuthOriginBlocked ErrorCode = "AUTH_ORIGIN_BLOCKED"

	// Correlation subsystem
	ErrCodeInvalidHeader ErrorCode = "INVALID_HEADER"

	// Cisco Inspect subsystem
	ErrCodeInvalidResponse ErrorCode = "INVALID_RESPONSE"

	// Subprocess (scanner/openshell) subsystem
	ErrCodeSubprocessExit ErrorCode = "SUBPROCESS_EXIT"

	// Webhook subsystem
	ErrCodeWebhookDeliveryFailed ErrorCode = "WEBHOOK_DELIVERY_FAILED"
	ErrCodeWebhookCooldown       ErrorCode = "WEBHOOK_COOLDOWN"

	// Quarantine subsystem
	ErrCodeFSMoveFailed ErrorCode = "FS_MOVE_FAILED"
	ErrCodeFSLinkFailed ErrorCode = "FS_LINK_FAILED"

	// Stream subsystem
	ErrCodeClientDisconnect ErrorCode = "CLIENT_DISCONNECT"
	ErrCodeUpstreamError    ErrorCode = "UPSTREAM_ERROR"
	ErrCodeStreamTimeout    ErrorCode = "STREAM_TIMEOUT"

	// SQLite subsystem
	ErrCodeSQLiteBusy ErrorCode = "SQLITE_BUSY"

	// Any subsystem
	ErrCodePanicRecovered ErrorCode = "PANIC_RECOVERED"

	// Scanner subsystem (LiteLLM bridge)
	ErrCodeLLMBridgeError ErrorCode = "LLM_BRIDGE_ERROR"

	// Gatewaylog subsystem — runtime schema validator (writer.go)
	// caught a payload that does not satisfy
	// schemas/gateway-event-envelope.json. Always paired with
	// SubsystemGatewaylog. The offending event is dropped from
	// sinks BEFORE the EventError fires; a non-zero rate of this
	// code indicates a producer bug, not a transient I/O issue.
	ErrCodeSchemaViolation ErrorCode = "SCHEMA_VIOLATION"
)

// Subsystem is the v7 standardized vocabulary for the `subsystem` field
// on every EventError emission. Shared with audit.Subsystem via the
// curated action registry - see internal/audit/actions.go.
type Subsystem string

const (
	SubsystemSidecar        Subsystem = "sidecar"
	SubsystemWatcher        Subsystem = "watcher"
	SubsystemGateway        Subsystem = "gateway"
	SubsystemScanner        Subsystem = "scanner"
	SubsystemPolicy         Subsystem = "policy"
	SubsystemGuardrail      Subsystem = "guardrail"
	SubsystemAuth           Subsystem = "auth"
	SubsystemConfig         Subsystem = "config"
	SubsystemInspect        Subsystem = "inspect"
	SubsystemApprovals      Subsystem = "approvals"
	SubsystemSink           Subsystem = "sink"
	SubsystemTelemetry      Subsystem = "telemetry"
	SubsystemCorrelation    Subsystem = "correlation"
	SubsystemStream         Subsystem = "stream"
	SubsystemCiscoInspect   Subsystem = "cisco-inspect"
	SubsystemOpenShell      Subsystem = "openshell"
	SubsystemWebhook        Subsystem = "webhook"
	SubsystemQuarantine     Subsystem = "quarantine"
	SubsystemAgentRegistry  Subsystem = "agent-registry"
	SubsystemSQLite         Subsystem = "sqlite"
	SubsystemAdmission      Subsystem = "admission"
	SubsystemConfigMutation Subsystem = "config_mutation"
	// Gatewaylog subsystem — owned by the structured writer itself
	// (runtime schema validation, fanout panics, forced drops).
	SubsystemGatewaylog Subsystem = "gatewaylog"
)

// AllErrorCodes returns every registered ErrorCode. Callers that need
// to enumerate (CI parity gate, JSON schema regeneration) should use
// this single source of truth rather than maintaining their own list.
func AllErrorCodes() []ErrorCode {
	return []ErrorCode{
		ErrCodeSinkDeliveryFailed,
		ErrCodeSinkQueueFull,
		ErrCodeExportFailed,
		ErrCodeConfigLoadFailed,
		ErrCodePolicyLoadFailed,
		ErrCodeAuthInvalidToken,
		ErrCodeAuthMissingToken,
		ErrCodeAuthCSRFMismatch,
		ErrCodeAuthOriginBlocked,
		ErrCodeInvalidHeader,
		ErrCodeInvalidResponse,
		ErrCodeSubprocessExit,
		ErrCodeWebhookDeliveryFailed,
		ErrCodeWebhookCooldown,
		ErrCodeFSMoveFailed,
		ErrCodeFSLinkFailed,
		ErrCodeClientDisconnect,
		ErrCodeUpstreamError,
		ErrCodeStreamTimeout,
		ErrCodeSQLiteBusy,
		ErrCodePanicRecovered,
		ErrCodeLLMBridgeError,
		ErrCodeSchemaViolation,
	}
}

// AllSubsystems returns every registered Subsystem.
func AllSubsystems() []Subsystem {
	return []Subsystem{
		SubsystemSidecar,
		SubsystemWatcher,
		SubsystemGateway,
		SubsystemScanner,
		SubsystemPolicy,
		SubsystemGuardrail,
		SubsystemAuth,
		SubsystemConfig,
		SubsystemInspect,
		SubsystemApprovals,
		SubsystemSink,
		SubsystemTelemetry,
		SubsystemCorrelation,
		SubsystemStream,
		SubsystemCiscoInspect,
		SubsystemOpenShell,
		SubsystemWebhook,
		SubsystemQuarantine,
		SubsystemAgentRegistry,
		SubsystemSQLite,
		SubsystemAdmission,
		SubsystemConfigMutation,
		SubsystemGatewaylog,
	}
}
