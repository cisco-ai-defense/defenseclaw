// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import (
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// CodeHookProcessFailOpen identifies an agent that may continue a tool call
// after its pre-tool hook dies or reaches the agent's timeout. A working
// gateway cannot observe a hook that never sent it a request.
const CodeHookProcessFailOpen = "hook_process_fail_open"

// AddHookProcessFailureWarnings reports the agent-side failure behavior of
// the enabled standalone connectors in connectors. This is distinct from
// effective_hook_fail_mode: that setting controls a running DefenseClaw
// hook's response to a gateway outage, not what the agent does when its hook
// process cannot answer. Every lifecycle action passes the connectors it
// described, whether or not it prints the connectors block, so ensure,
// install and repair never report security_complete where status and verify
// report this limit.
func (r *Result) AddHookProcessFailureWarnings(connectors map[string]ConnectorState) {
	if r == nil || r.Profile != "standalone" {
		return
	}
	for _, name := range []string{"antigravity", "claudecode", "codex", "copilot", "devin", "hermes", "kiro"} {
		state, ok := connectors[name]
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

// Every Hermes deployment keeps the killed-hook warning. Only versions in
// the reviewed v2 contract receive the narrower timeout message.
func hermesTimeoutClosed(versions []string) bool {
	if len(versions) == 0 {
		return false
	}
	for _, version := range versions {
		resolved := connector.ResolveHookContractStrict("hermes", version)
		if resolved.Status != connector.HookCompatibilityKnown || resolved.Contract.ContractID != "hermes-hooks-v2" {
			return false
		}
	}
	return true
}
