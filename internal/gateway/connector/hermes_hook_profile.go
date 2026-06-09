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

// Hermes owns a dedicated HookProfile (Decode + Respond) rather than
// sharing the generic hook_only_profile.go switch. The independence
// matters because Hermes is the one hook-only connector whose
// inspectable content does NOT live at the top level of the hook
// payload: Hermes pipes a flat envelope
//
//	{
//	  "hook_event_name": "pre_llm_call",
//	  "tool_name":       null,
//	  "tool_input":      null,
//	  "session_id":      "sess_abc123",
//	  "cwd":             "/home/user/project",
//	  "extra":           {"user_message": "...", "result": "...", ...}
//	}
//
// and stashes the prompt (pre_llm_call → extra.user_message), the tool
// result (post_tool_call → extra.result), the model response
// (post_llm_call → extra.assistant_response), and lifecycle metadata
// inside the per-event `extra` object. The generic
// normalizeAgentHookRequest only reads top-level prompt/result keys, so
// without this decoder prompt- and result-content rules would inspect
// an EMPTY string on every Hermes pre_llm_call / post_tool_call and the
// expanded hermes-hooks-v2 coverage would be declared but inert.
//
// # Hermes shell-hook lifecycle (cli-config.yaml `hooks:` block)
//
//	Event            | Direction   | DefenseClaw role
//	-----------------+-------------+--------------------------------------
//	pre_llm_call     | prompt      | inspect user prompt; inject context
//	pre_tool_call    | tool_call   | inspect tool args; BLOCK
//	post_tool_call   | tool_result | inspect tool output (observe)
//	post_llm_call    | tool_result | inspect model output (telemetry)
//	on_session_start | (audit)     | session lifecycle telemetry
//	on_session_end   | (audit)     | session lifecycle telemetry
//	subagent_stop    | (audit)     | delegate-task telemetry
//
// Only pre_tool_call can block: Hermes reads a blocking stdout response
// for pre_tool_call and a {"context":...} injection for pre_llm_call,
// and ignores the stdout of every other event. Hermes never blocks on a
// non-zero exit code or a hook timeout (it logs a warning), so there is
// no fail-closed surface — SupportsFailClosed stays false in the
// contract. Hermes accepts both {"action":"block","message"} (its
// canonical shape) and {"decision":"block","reason"} (the Claude-Code
// style it normalizes internally); we emit the latter for wire parity
// with the legacy gateway shaper (hookOutputFor) and the pinned
// hermes/verdict-blocked golden.

// hermesProfileDecode implements HookProfile.Decode for Hermes. It runs
// AFTER the generic normalizeAgentHookRequest and only overrides the
// fields the generic decoder cannot resolve from Hermes' enveloped
// payload (everything it leaves blank is inherited). pre_tool_call is
// intentionally absent from the switch: the generic decoder already
// reads top-level tool_name/tool_input correctly for that event.
func hermesProfileDecode(payload map[string]interface{}) HookProfileRequest {
	req := HookProfileRequest{
		ConnectorName: "hermes",
		AgentName:     "hermes",
		AgentType:     "hermes",
		HookEventName: hookFirstString(payload, "hook_event_name", "hookEventName"),
		SessionID:     hookFirstString(payload, "session_id", "sessionId"),
		Payload:       payload,
	}
	extra, _ := payload["extra"].(map[string]interface{})
	switch canonicalHookEvent(req.HookEventName) {
	case "prellmcall":
		// pre_llm_call carries the user's message in extra.user_message.
		// Direction/ToolName already resolve to prompt/message via the
		// generic prompt-event classifier; we add the missing content.
		req.Direction = "prompt"
		req.ToolName = "message"
		req.Content = hermesEnvelopeString(payload, extra, "user_message", "userMessage", "prompt")
	case "posttoolcall":
		// post_tool_call carries the tool's output in extra.result.
		req.Direction = "tool_result"
		req.ToolName = hookFirstString(payload, "tool_name", "toolName")
		req.Content = hermesEnvelopeString(payload, extra, "result", "tool_result", "toolResult", "output")
	case "postllmcall":
		// post_llm_call carries the model's final response. It is
		// telemetry on Hermes (its stdout is ignored), but we surface the
		// content for the audit envelope.
		req.Direction = "tool_result"
		req.ToolName = "message"
		req.Content = hermesEnvelopeString(payload, extra, "assistant_response", "assistantResponse", "response")
	case "onsessionstart", "onsessionend":
		req.ToolName = "session"
	case "subagentstop":
		req.ToolName = "subagent"
		req.Content = hermesEnvelopeString(payload, extra, "child_summary", "childSummary")
	}
	return req
}

// hermesProfileRespond implements HookProfile.Respond for Hermes. It is
// wire-identical to the legacy gateway shaper (hookOutputFor's "hermes"
// case) and the hermes/verdict-blocked golden: pre_tool_call blocks via
// {"decision":"block","reason"}; pre_llm_call injects via {"context":...}
// when there is additional context to surface. Every other event is
// observe-only — Hermes ignores its stdout — so we return a nil body and
// the outcome travels via the response envelope's top-level Action field.
func hermesProfileRespond(in HookRespondInput) HookRespondOutput {
	reason := connectorReasonForProfile("hermes", in.Action, in.Req.ToolName, in.Reason)
	var output map[string]interface{}
	if in.Action == "block" {
		output = map[string]interface{}{"decision": "block", "reason": reason}
	} else if canonicalHookEvent(in.Req.HookEventName) == "prellmcall" && in.AdditionalContext != "" {
		output = map[string]interface{}{"context": in.AdditionalContext}
	}
	return HookRespondOutput{FieldName: "hook_output", Output: output}
}

// hermesEnvelopeString returns the first non-empty value among the given
// keys, checking the per-event `extra` object first (where Hermes nests
// content) and then the top level as a defensive fallback for any future
// payload that flattens the field.
func hermesEnvelopeString(payload, extra map[string]interface{}, keys ...string) string {
	if extra != nil {
		if s := hookFirstString(extra, keys...); s != "" {
			return s
		}
	}
	return hookFirstString(payload, keys...)
}
