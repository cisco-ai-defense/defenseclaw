// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

// ownWindowsRuntimePending reports whether the Windows standalone hook of
// connector refuses the account sid as enterprise_managed_enrollment_pending.
// The Windows build replaces it with the machine-file check; everywhere else
// it claims nothing.
var ownWindowsRuntimePending = func(connector, sid string) bool { return false }

// ownCauseBlockedUntilSignIn: the connector's machine hook is registered for
// the account and refuses every tool call until the guardian publishes the
// account's runtime in its connected session (GAP-1034). The reason is the
// wording the administrator's status and verify use for the same rows and the
// hook's refusal states the same fact.
var ownCauseBlockedUntilSignIn = ownCause{"pending_sign_in",
	"blocked until this account signs in or reconnects (DefenseClaw refuses every tool call of the agent)",
	"Stay signed in to Windows in a connected session (console or Remote Desktop; not SSH or a scheduled task); " +
		"DefenseClaw enrolls the account within about 5 minutes, then restart the agent and run defenseclaw status again, " +
		"and ask IT if it stays blocked"}

// ownBlocked is the row of a connector the hook refuses until its account has
// a connected session. A script matching the state sees "blocked" and protected
// false.
func ownBlocked(cause ownCause) map[string]any {
	return ownRow(false, "blocked", cause)
}

// ownConnectorRowBlocked reports whether connectors[name] is the blocked row.
func ownConnectorRowBlocked(connectors map[string]any, name string) bool {
	row, ok := connectors[name].(map[string]any)
	return ok && row["state"] == "blocked"
}
