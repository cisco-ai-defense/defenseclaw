// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import "encoding/json"

// The wording of a connector whose machine hook refuses every tool call until
// its account has a connected session (GAP-1034). The reason is the sentence
// the administrator's status and verify use for the same rows
// (windowsEnterpriseEnrollmentBlocked), and the hook's refusal states the same
// fact.
const (
	ownStatusBlockedCode   = "pending_sign_in"
	ownStatusBlockedReason = "blocked until this account signs in or reconnects (DefenseClaw refuses every tool call of the agent)"
	ownStatusBlockedNext   = "Stay signed in to Windows in a connected session (console or Remote Desktop; not SSH or a scheduled task); " +
		"DefenseClaw enrolls the account within about 5 minutes, then restart the agent and run defenseclaw status again, " +
		"and ask IT if it stays blocked"
	ownStatusBlockedCowork = "blocked until this account signs in or reconnects (Cowork runs the Claude Code hooks, which refuse every tool call)"
)

// ownStatusMachineHookConnectors are the connectors the standalone hook can
// refuse as enterprise_managed_enrollment_pending: the machine-hook connectors.
var ownStatusMachineHookConnectors = []string{"claudecode", "codex", "cursor"}

// overlayOwnStatusPending turns the rows of the own-status answer body that the
// caller's own hook refuses as enrollment pending into blocked rows. pending
// reports it for one connector. Only a row the gateway called protected or not
// confirmed changes: an unprotected, excluded or removed row keeps the more
// specific state it has, and a row the hook would let through keeps its state.
// Claude Code and Cowork follow the Claude Code row. A body that does not
// decode, or that lists none of the connectors, is returned as it was.
func overlayOwnStatusPending(body []byte, pending func(connector string) bool) []byte {
	var answer map[string]any
	if json.Unmarshal(body, &answer) != nil {
		return body
	}
	connectors, _ := answer["connectors"].(map[string]any)
	changed := false
	for _, name := range ownStatusMachineHookConnectors {
		row, ok := connectors[name].(map[string]any)
		if !ok {
			continue
		}
		if state, _ := row["state"].(string); state != "protected" && state != "not confirmed" {
			continue
		}
		if !pending(name) {
			continue
		}
		connectors[name] = map[string]any{
			"protected":   false,
			"state":       "blocked",
			"reason_code": ownStatusBlockedCode,
			"reason":      ownStatusBlockedReason,
			"next_step":   ownStatusBlockedNext,
		}
		changed = true
		if name == "claudecode" {
			answer["claude_code"] = map[string]any{"protected": false}
			if cowork, _ := answer["cowork"].(map[string]any); cowork != nil {
				if state, _ := cowork["state"].(string); state == "protected" {
					cowork["protected"] = false
					cowork["state"] = "blocked"
					cowork["reason_code"] = ownStatusBlockedCode
					cowork["reason"] = ownStatusBlockedCowork
				}
			}
		}
	}
	if !changed {
		return body
	}
	encoded, err := json.Marshal(answer)
	if err != nil {
		return body
	}
	return encoded
}
