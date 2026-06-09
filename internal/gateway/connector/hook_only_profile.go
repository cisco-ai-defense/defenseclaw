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

package connector

import (
	"fmt"
	"strings"
)

func hookOnlyProfileMapVerdict(in HookVerdictInput) HookVerdictOutput {
	raw := normalizedGuardrailAction(in.RawAction)
	if raw == "" {
		raw = "allow"
	}
	if in.Mode != "action" {
		return HookVerdictOutput{Action: "allow", WouldBlock: raw == "block"}
	}
	switch raw {
	case "block":
		if in.Caps.CanBlock && eventInProfile(in.Event, in.Caps.BlockEvents) {
			return HookVerdictOutput{Action: "block", WouldBlock: false}
		}
		return HookVerdictOutput{Action: "allow", WouldBlock: true}
	case "confirm":
		if in.Caps.CanAskNative && eventInProfile(in.Event, in.Caps.AskEvents) {
			return HookVerdictOutput{Action: "confirm", WouldBlock: false}
		}
		return HookVerdictOutput{Action: "alert", WouldBlock: false}
	default:
		return HookVerdictOutput{Action: raw, WouldBlock: false}
	}
}

func hookOnlyProfileRespond(in HookRespondInput) HookRespondOutput {
	reason := connectorReasonForProfile(in.Req.ConnectorName, in.Action, in.Req.ToolName, in.Reason)
	var output map[string]interface{}
	switch in.Req.ConnectorName {
	// NOTE: hermes is intentionally absent — it owns a dedicated
	// profile (hermes_hook_profile.go: hermesProfileRespond) wired in
	// hookOnlyConnector.HookProfile, so it no longer shares this switch.
	case "cursor":
		switch in.Action {
		case "block":
			output = map[string]interface{}{"continue": true, "permission": "deny", "user_message": reason, "agent_message": reason}
		case "confirm":
			output = map[string]interface{}{"continue": true, "permission": "ask", "user_message": reason, "agent_message": reason}
		case "alert":
			if in.AdditionalContext != "" {
				output = map[string]interface{}{"continue": true, "permission": "allow", "agent_message": in.AdditionalContext}
			}
		}
	case "windsurf":
		if in.Action == "block" {
			output = map[string]interface{}{"message": reason}
		}
	case "geminicli":
		if in.Action == "block" {
			output = map[string]interface{}{"decision": "deny", "reason": reason}
		} else if in.Action == "alert" && in.AdditionalContext != "" {
			output = map[string]interface{}{"systemMessage": in.AdditionalContext}
		}
	case "copilot":
		output = copilotHookOutputForProfile(in.Req.HookEventName, in.Action, in.RawAction, reason, in.AdditionalContext)
	case "openhands":
		if in.Action == "block" {
			output = map[string]interface{}{"decision": "deny", "reason": reason}
		} else if (in.Action == "alert" || in.RawAction == "confirm") && in.AdditionalContext != "" {
			output = map[string]interface{}{"additionalContext": in.AdditionalContext}
		}
	case "opencode":
		// The DefenseClaw bridge plugin reads .decision and throws on
		// "deny"/"block" to abort the tool. opencode has no hook-driven
		// ask or context-injection channel, so only block surfaces a
		// body; everything else is observe-only.
		if in.Action == "block" {
			output = map[string]interface{}{"decision": "deny", "reason": reason}
		}
	case "antigravity":
		output = antigravityHookOutputForProfile(in.Req.HookEventName, in.Action, in.RawAction, reason, in.AdditionalContext)
	}
	if output == nil && in.RawAction == "confirm" && in.AdditionalContext != "" && !in.Caps.CanAskNative {
		output = map[string]interface{}{"systemMessage": in.AdditionalContext}
	}
	return HookRespondOutput{FieldName: "hook_output", Output: output}
}

// antigravityHookOutputForProfile renders the per-event hook
// response wire shape Antigravity (`agy`) expects per the 2.0
// lifecycle spec. Spec source (Antigravity 2.0 hook docs):
//
//	Event           | DefenseClaw hook role
//	----------------+----------------------------------------------
//	PreInvocation   | Inspect prompt + transcript before LLM call;
//	                | block / ask / inject context.
//	PreToolUse      | Inspect tool call args; block / ask / alert.
//	                | (Empirically verified on agy v1.0.1.)
//	PostToolUse     | Inspect tool output after run; cannot block
//	                | (tool already executed) — surface findings as
//	                | additionalContext for next-turn ingestion.
//	PostInvocation  | Inspect LLM response + final state; cannot
//	                | block (response already generated) — surface
//	                | findings as additionalContext.
//	Stop            | Per spec: "block-terminating the agent if
//	                | validation checks fail." Distinct from
//	                | PreInvocation/PreToolUse "deny" verb because
//	                | the spec phrases Stop's block as preventing
//	                | termination, not preventing an action.
//
// Action → wire decision mapping:
//
//	block on PreInvocation/PreToolUse → {decision: "deny",  reason}
//	block on Stop                     → {decision: "block", reason}
//	confirm                           → {decision: "ask",   reason} (Pre* only)
//	alert with additional context     → {systemMessage}
//	alert on Post* events             → {additionalContext}
//
// PostToolUse and PostInvocation NEVER emit deny/ask: by the time
// these events fire the inspected action has already executed at
// the agent layer, so blocking would be ineffective theatre.
// Findings surface as additionalContext (the Claude-Code post-event
// idiom agy borrows verbatim), which agy ingests as model-readable
// context for the next turn.
//
// Empirical confidence:
//   - PreToolUse: verified on agy v1.0.1 — {decision: "deny"} blocks,
//     {decision: "ask"} prompts, both bypass --dangerously-skip-permissions.
//   - PreInvocation, PostToolUse, PostInvocation, Stop: not yet
//     verified empirically on agy v1.0.x. The wire shapes here
//     follow agy's Claude-Code lineage; if empirical testing reveals
//     agy uses different verbs / fields for these events, this
//     function is the single edit point. Tests in
//     hook_profile_dispatch_test.go and antigravity_hook_profile_test.go
//     pin the current contract so divergences surface in CI.
func antigravityHookOutputForProfile(event, action, rawAction, reason, additional string) map[string]interface{} {
	switch canonicalHookEvent(event) {
	case "preinvocation", "pretooluse":
		switch action {
		case "block":
			return map[string]interface{}{"decision": "deny", "reason": reason}
		case "confirm":
			return map[string]interface{}{"decision": "ask", "reason": reason}
		case "alert":
			if additional != "" {
				return map[string]interface{}{"systemMessage": additional}
			}
		}
	case "stop":
		// Spec phrases Stop's block verb as "block-terminating the
		// agent if validation checks fail" — the wire string is
		// "block" (matching agy's Claude-Code lineage for Stop
		// hooks), distinct from "deny" used by Pre* events. If
		// empirical testing on agy v1.0.x reveals "block" is not
		// honored on Stop, the safe fallback is "deny" (verified
		// for PreToolUse on the same agy version).
		switch action {
		case "block":
			return map[string]interface{}{"decision": "block", "reason": reason}
		case "alert":
			if additional != "" {
				return map[string]interface{}{"systemMessage": additional}
			}
		}
	case "posttooluse", "postinvocation":
		// Post* events fire after execution — DefenseClaw cannot
		// retroactively block the inspected action. Findings
		// surface as additionalContext for next-turn ingestion;
		// agy's Claude-Code-derived schema treats this field as
		// model-readable context that gets injected into the next
		// LLM call automatically.
		if additional != "" {
			return map[string]interface{}{"additionalContext": additional}
		}
	}
	// Forward-compat fallback: unknown / unrecognised events with
	// confirm verdicts and additional context surface as
	// systemMessage, matching the legacy hook-only fallback at the
	// bottom of hookOnlyProfileRespond.
	if rawAction == "confirm" && additional != "" {
		return map[string]interface{}{"systemMessage": additional}
	}
	return nil
}

func copilotHookOutputForProfile(event, action, rawAction, reason, additional string) map[string]interface{} {
	switch canonicalHookEvent(event) {
	case "pretooluse":
		switch action {
		case "confirm":
			return map[string]interface{}{"permissionDecision": "ask", "permissionDecisionReason": reason}
		case "block":
			return map[string]interface{}{"permissionDecision": "deny", "permissionDecisionReason": reason}
		}
	case "permissionrequest":
		if action == "block" {
			return map[string]interface{}{"behavior": "deny", "message": reason, "interrupt": true}
		}
	case "agentstop", "stop", "subagentstop":
		if action == "block" {
			return map[string]interface{}{"decision": "block", "reason": reason}
		}
	case "posttoolusefailure", "notification":
		if additional != "" {
			return map[string]interface{}{"additionalContext": additional}
		}
	}
	if rawAction == "confirm" && additional != "" {
		return map[string]interface{}{"additionalContext": additional}
	}
	return nil
}

func connectorReasonForProfile(connectorName, action, tool, reason string) string {
	if r := strings.TrimSpace(reason); r != "" {
		return r
	}
	tool = strings.TrimSpace(tool)
	switch action {
	case "block":
		if tool == "" {
			return "DefenseClaw blocked this action. Run `defenseclaw mcp list` or `skill list` to review approved assets."
		}
		return fmt.Sprintf("DefenseClaw blocked %s. Run `defenseclaw mcp list` or `skill list` to review approved assets.", tool)
	case "confirm":
		if tool == "" {
			return "DefenseClaw needs your approval before this action can run."
		}
		return fmt.Sprintf("DefenseClaw needs your approval before %s can run.", tool)
	case "alert", "allow_with_warning":
		if tool == "" {
			return "DefenseClaw flagged this action with a warning."
		}
		return fmt.Sprintf("DefenseClaw flagged %s with a warning.", tool)
	default:
		return fmt.Sprintf("Allowed by DefenseClaw %s policy.", connectorName)
	}
}
