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
	"runtime"
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

func hermesProfileMapVerdict(in HookVerdictInput) HookVerdictOutput {
	raw := normalizedGuardrailAction(in.RawAction)
	if in.Mode == "action" && raw == "block" &&
		canonicalHookEvent(in.Event) == "preverify" {
		// "continue" is Hermes' documented bounded verification control. It
		// neither vetoes the operation nor upgrades pre_verify into a block
		// event, and observe mode continues to use the shared audit-only map.
		return HookVerdictOutput{Action: "continue", WouldBlock: false}
	}
	return hookOnlyProfileMapVerdict(in)
}

func hookOnlyProfileRespond(in HookRespondInput) HookRespondOutput {
	reason := connectorReasonForProfile(in.Req.ConnectorName, in.Action, in.Req.ToolName, in.Reason)
	var output map[string]interface{}
	switch in.Req.ConnectorName {
	case "hermes":
		// Hermes v0.19 shell-hook lifecycle (config.yaml `hooks:` block):
		//
		//	pre_tool_call       → BLOCK with valid JSON (only tool veto)
		//	pre_llm_call        → inject {"context":...}
		//	pre_verify          → bounded {"action":"continue",...}
		//	remaining 20 events → attributed audit from the shell lane
		//
		// Python transform/gateway plugin hooks have response semantics that
		// Hermes' shell JSON parser cannot express; approval/API/Kanban and
		// ordinary lifecycle responses are ignored or undocumented. We never
		// infer response authority from VALID_HOOKS membership. Hermes accepts both
		// {"action":"block","message"} (its canonical shape) and
		// {"decision":"block","reason"} (the Claude-Code style it
		// normalizes internally); we emit the latter for wire parity
		// with the legacy shaper (hookOutputFor) and the pinned
		// hermes/verdict-blocked golden. Confirm verdicts intentionally
		// return no hook_output: Hermes has no documented ask, approve,
		// or system-message response shape. The gateway still records and
		// alerts the downgraded finding.
		event := canonicalHookEvent(in.Req.HookEventName)
		if in.Action == "block" && event == "pretoolcall" {
			output = map[string]interface{}{"decision": "block", "reason": reason}
		} else if in.Action == "continue" && event == "preverify" {
			output = map[string]interface{}{"action": "continue", "message": reason}
		} else if event == "prellmcall" && in.AdditionalContext != "" {
			output = map[string]interface{}{"context": in.AdditionalContext}
		}
	case "cursor":
		output = CursorHookOutput(in.Req.HookEventName, in.Action, reason, in.AdditionalContext)
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
		} else if canonicalHookEvent(in.Req.HookEventName) == "userpromptsubmit" &&
			(in.Action == "alert" || in.RawAction == "confirm") && in.AdditionalContext != "" {
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
	case "omnigent":
		// The installed Python policy reads the unified top-level action
		// and translates allow/block/confirm to ALLOW/DENY/ASK. No nested
		// hook_output body is required by OmniGent's policy API.
		return HookRespondOutput{}
	}
	if output == nil && in.Req.ConnectorName != "hermes" &&
		in.RawAction == "confirm" && in.AdditionalContext != "" && !in.Caps.CanAskNative {
		output = map[string]interface{}{"systemMessage": in.AdditionalContext}
	}
	return HookRespondOutput{FieldName: "hook_output", Output: output}
}

// CursorHookOutput renders the exact event-native stdout object documented by
// Cursor. It is shared by the profile path and the legacy gateway fallback so
// neither path can reintroduce generic fields that an event does not accept.
func CursorHookOutput(event, action, reason, additional string) map[string]interface{} {
	event = canonicalHookEvent(event)
	switch event {
	case "beforesubmitprompt":
		if action == "block" {
			return map[string]interface{}{"continue": false, "user_message": reason}
		}
		return map[string]interface{}{"continue": true}
	case "stop", "subagentstop":
		// Cursor stop/subagentStop hooks cannot veto the completed lifecycle
		// transition. Their only documented response is followup_message,
		// which starts a bounded follow-up turn.
		message := additional
		if message == "" && action != "allow" {
			message = reason
		}
		if message != "" {
			return map[string]interface{}{"followup_message": message}
		}
		return map[string]interface{}{}
	case "sessionstart", "posttooluse":
		// DefenseClaw does not mutate session environment or tool results.
		// It can supply only the documented context field when the evaluator
		// produced attributed context for these events.
		if additional != "" {
			return map[string]interface{}{"additional_context": additional}
		}
		return map[string]interface{}{}
	case "precompact":
		if additional != "" {
			return map[string]interface{}{"user_message": additional}
		}
		return map[string]interface{}{}
	case "pretooluse":
		return cursorPermissionOutput(action, reason, false, true, true)
	case "subagentstart", "beforereadfile":
		return cursorPermissionOutput(action, reason, false, true, false)
	case "beforetabfileread":
		return cursorPermissionOutput(action, reason, false, false, false)
	case "beforeshellexecution", "beforemcpexecution":
		return cursorPermissionOutput(action, reason, true, true, true)
	default:
		// sessionEnd, postToolUseFailure, all after* observation events, and
		// workspaceOpen have no DefenseClaw-owned event output. workspaceOpen
		// accepts pluginPaths, but this connector does not inject plugins.
		return map[string]interface{}{}
	}
}

func cursorPermissionOutput(action, reason string, supportsAsk, supportsUserMessage, supportsAgentMessage bool) map[string]interface{} {
	permission := "allow"
	if action == "block" {
		permission = "deny"
	} else if action == "confirm" && supportsAsk {
		permission = "ask"
	}
	output := map[string]interface{}{"permission": permission}
	if permission == "allow" {
		return output
	}
	if supportsUserMessage {
		output["user_message"] = reason
	}
	if supportsAgentMessage {
		output["agent_message"] = reason
	}
	return output
}

// antigravityHookOutputForProfile renders only fields documented by
// https://antigravity.google/docs/hooks. PreToolUse is the sole hard policy
// boundary: synchronous stdout {"decision":"deny"} blocks the tool. No
// enforcement claim relies on the hook process exit code.
func antigravityHookOutputForProfile(event, action, _ string, reason, additional string) map[string]interface{} {
	switch canonicalHookEvent(event) {
	case "pretooluse":
		switch action {
		case "block":
			return map[string]interface{}{"decision": "deny", "reason": reason}
		case "confirm":
			return map[string]interface{}{"decision": "ask", "reason": reason}
		default:
			return map[string]interface{}{"decision": "allow"}
		}
	case "preinvocation", "postinvocation":
		if additional != "" {
			return map[string]interface{}{
				"injectSteps": []interface{}{
					map[string]interface{}{"ephemeralMessage": additional},
				},
			}
		}
		return map[string]interface{}{}
	case "posttooluse":
		return map[string]interface{}{}
	case "stop":
		// The documented "continue" decision re-enters the agent loop. That is
		// not a tool-execution block and DefenseClaw does not present it as one.
		return map[string]interface{}{"decision": "allow"}
	}
	return map[string]interface{}{}
}

func copilotHookOutputForProfile(event, action, rawAction, reason, additional string) map[string]interface{} {
	switch canonicalHookEvent(event) {
	case "userprompttransformed":
		// This event is mutation-only. DefenseClaw observes it but does not
		// rewrite the transformed prompt, so the valid no-op response is {}.
		return map[string]interface{}{}
	case "pretooluse":
		switch action {
		case "confirm":
			return map[string]interface{}{"permissionDecision": "ask", "permissionDecisionReason": reason}
		case "block":
			return map[string]interface{}{"permissionDecision": "deny", "permissionDecisionReason": reason}
		}
	case "permissionrequest":
		if action == "block" {
			// interrupt=true stops the entire Copilot agent. An ordinary
			// DefenseClaw tool denial must short-circuit only this permission
			// request, so leave the optional interrupt field absent.
			out := map[string]interface{}{"behavior": "deny", "message": reason}
			if runtime.GOOS == "darwin" {
				out["interrupt"] = true
			}
			return out
		}
	case "agentstop", "stop", "subagentstop":
		if action == "block" {
			return map[string]interface{}{"decision": "block", "reason": reason}
		}
	case "sessionstart", "subagentstart", "posttooluse", "posttoolusefailure", "notification":
		if additional != "" {
			return map[string]interface{}{"additionalContext": additional}
		}
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
