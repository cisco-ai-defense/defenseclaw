// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

// ForeignHookSessionPathPrefix is the standalone gateway's scoped session
// route. The connector name following the prefix selects its hook authority.
const ForeignHookSessionPathPrefix = "/api/v1/foreign-hook-session/"

// SessionExchange is the scan supplied by the administrator-owned hook. The
// gateway selects the storage namespace from the transport-verified caller,
// never from a field in this message.
type SessionExchange struct {
	Key          SessionKey    `json:"key"`
	SessionStart bool          `json:"session_start"`
	Decision     GuardDecision `json:"decision"`
	// Event and Tool name the hook event and the tool it was checked for,
	// as the agent's payload reported them ("" when it named none). They
	// only label the gateway's export of a denial (a tool span for a tool
	// call, an apply_guardrail span for a session or prompt event); the
	// decision never depends on them.
	Event string `json:"event,omitempty"`
	Tool  string `json:"tool,omitempty"`
}
