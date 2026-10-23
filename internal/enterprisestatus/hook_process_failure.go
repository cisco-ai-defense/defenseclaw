// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import (
	"slices"
	"strings"
)

// CodeHookProcessFailOpen identifies an agent that may continue a tool call
// after its pre-tool hook dies or reaches the agent's timeout. A working
// gateway cannot observe a hook that never sent it a request.
const CodeHookProcessFailOpen = "hook_process_fail_open"

// AddHookProcessFailureWarnings reports the agent-side failure behavior of
// enabled standalone connectors. This is distinct from effective_hook_fail_mode:
// that setting controls a running DefenseClaw hook's response to a gateway
// outage, not what the agent does when its hook process cannot answer.
func (r *Result) AddHookProcessFailureWarnings() {
	if r == nil || r.Profile != "standalone" || (r.Action != "status" && r.Action != "verify") {
		return
	}
	for _, name := range []string{"antigravity", "claudecode", "codex", "copilot", "devin", "hermes", "kiro"} {
		state, ok := r.Connectors[name]
		if !ok || !state.Enabled {
			continue
		}
		var behavior string
		switch name {
		case "antigravity":
			behavior = "a command hook that cannot start or reaches its timeout has no vendor-guaranteed deny"
		case "claudecode", "codex":
			behavior = "a killed PreToolUse hook or PreToolUse timeout is non-blocking"
		case "copilot":
			behavior = "a timed-out preToolUse hook is non-blocking; a later permission hook may still deny"
		case "devin":
			behavior = "a killed pre-tool hook is non-blocking"
		case "hermes":
			if hermesTimeoutClosed(state.Versions) {
				behavior = "a killed pre_tool_call hook can still fail open with fail_closed: true; the reviewed 0.21 contract blocks spawn errors and timeouts, not a non-2 process exit"
			} else {
				behavior = "a pre-0.21 or unknown-version pre_tool_call hook can fail open when killed or timed out; the reviewed 0.21 contract closes timeout but not kill"
			}
		case "kiro":
			behavior = "a preToolUse hook timeout is non-blocking in the reviewed CLI 2.x path"
		}
		r.AddWarning(CodeHookProcessFailOpen, name+": "+behavior+
			"; the tool may run without a DefenseClaw decision or pre-tool audit row if the hook never reaches the gateway. Protect the hook process from user signals with application control or EDR; see the managed connector limits")
		r.SecurityComplete = false
	}
}

// The reviewed Hermes v2 contract begins at 0.21 and includes these dated
// pins. Every Hermes deployment keeps the killed-hook warning; this check
// selects the narrower message when every reported version blocks timeouts.
func hermesTimeoutClosed(versions []string) bool {
	if len(versions) == 0 {
		return false
	}
	for _, version := range versions {
		if strings.HasPrefix(version, "0.21.") {
			continue
		}
		if slices.Contains([]string{"2026.8.31", "2026.9.7", "2026.9.11", "2026.9.14", "2026.9.21", "2026.9.24"}, version) {
			continue
		}
		return false
	}
	return true
}
