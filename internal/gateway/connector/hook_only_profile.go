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
	case "hermes":
		if in.Action == "block" {
			output = map[string]interface{}{"decision": "block", "reason": reason}
		} else if in.Req.HookEventName == "pre_llm_call" && in.AdditionalContext != "" {
			output = map[string]interface{}{"context": in.AdditionalContext}
		}
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
	}
	if output == nil && in.RawAction == "confirm" && in.AdditionalContext != "" && !in.Caps.CanAskNative {
		output = map[string]interface{}{"systemMessage": in.AdditionalContext}
	}
	return HookRespondOutput{FieldName: "hook_output", Output: output}
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
