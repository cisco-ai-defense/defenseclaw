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
	"strings"
)

// antigravityProfileDecode implements HookProfile.Decode for Google's
// Antigravity (`agy`) CLI / IDE. agy emits Claude-Code-derived hook
// payloads — fields are nested rather than flat — so the unified
// gateway decoder (normalizeAgentHookRequest) cannot extract event
// names or tool descriptors without a connector-specific decoder.
// Without this decoder, the unified handler returns HTTP 400
// ("hook event name is required") on every agy hook POST.
//
// # Antigravity 2.0 lifecycle events
//
// The agy 2.0 hook spec defines five lifecycle events; this decoder
// recognises all five and routes each onto the canonical
// HookProfileRequest fields the unified evaluator's
// classifier-driven dispatch (isPromptLikeEvent /
// isResultLikeEvent / isGenericToolInspectionEvent in agent_hook.go)
// expects.
//
//	Event           | Direction    | Unified handler routes to
//	----------------+--------------+----------------------------------
//	PreInvocation   | prompt       | inspectMessageContent (prompt)
//	PreToolUse      | tool_call    | inspectToolPolicy + asset policy
//	PostToolUse     | tool_result  | inspectMessageContent (tool_result)
//	PostInvocation  | tool_result  | inspectMessageContent (tool_result)
//	Stop            | tool_result  | (default branch — audit only)
//
// # Payload shapes
//
// agy's PreToolUse payload (empirically verified against agy v1.0.1):
//
//	{
//	  "hookEventName":    "PreToolUse",
//	  "toolCall":         {"name": "run_command", "args": {...}},
//	  "conversationId":   "f74b1ea2-...",
//	  "stepIdx":           21,
//	  "transcriptPath":   "/...",
//	  "workspacePaths":   ["/tmp/agy-smoketest"],
//	  "artifactDirectoryPath": "/..."
//	}
//
// PostToolUse, PreInvocation, PostInvocation, and Stop payload shapes
// are NOT empirically verified for agy v1.0.x — the spec defines the
// events but the v1.0.1 binary may not yet emit all of them, and field
// names are not prescribed by the spec. The decoder uses defensive
// keypath fallbacks (camelCase + snake_case + nested object lookups)
// so that whatever shape agy ships will project onto the canonical
// request fields. As agy versions tick up and we observe real
// payloads, the keypath lists below are the right place to add newly
// observed field names.
//
// # Backward compat
//
// agy v1.0.0 / v1.0.1 PreToolUse payloads pre-date the spec'd
// `hookEventName` field; antigravityInferEvent provides a structural
// inference fallback (toolCall present → PreToolUse, etc.) so older
// payloads continue to decode correctly when agy starts shipping the
// explicit field name only on newer events.
func antigravityProfileDecode(payload map[string]interface{}) HookProfileRequest {
	req := HookProfileRequest{
		ConnectorName: "antigravity",
		AgentName:     "antigravity",
		AgentType:     "antigravity",
		Payload:       payload,
	}

	// Common metadata extracted from every event payload. agy uses
	// `conversationId` as the stable session identifier. `stepIdx` is
	// a trajectory step, not a prompt/response turn, so it remains in
	// the preserved payload and is never projected onto TurnID.
	req.SessionID = hookFirstString(payload,
		"conversationId", "conversation_id",
		"session_id", "sessionId",
	)
	req.TurnID = hookFirstString(payload, "turn_id", "turnId", "turnID")

	// Resolve the event name. Prefer agy's explicit hookEventName /
	// hook_event_name field per the 2.0 spec; fall back to structural
	// inference for legacy payloads predating the explicit field.
	if explicit := hookFirstString(payload, "hookEventName", "hook_event_name"); explicit != "" {
		req.HookEventName = explicit
	} else {
		req.HookEventName = antigravityInferEvent(payload)
	}

	// Per-event field extraction. Direction is set per branch so the
	// unified evaluator's classifier-driven dispatch (in
	// agent_hook.go) routes correctly to inspectMessageContent /
	// inspectToolPolicy. Stop has no inspection target — falls
	// through to the default audit-only branch in evaluateAgentHook.
	switch antigravityCanonicalEvent(req.HookEventName) {
	case "preinvocation":
		req.Direction = "prompt"
		req.ToolName = "message"
		req.Content = antigravityExtractPrompt(payload)
	case "pretooluse":
		req.Direction = "tool_call"
		antigravityExtractToolCall(&req, payload)
	case "posttooluse":
		req.Direction = "tool_result"
		antigravityExtractToolCall(&req, payload)
		// PostToolUse content is the tool's RESPONSE, not the call.
		// Override Content (set above to the call command) when the
		// payload carries a toolResponse field.
		if response := antigravityExtractToolResponse(payload); response != "" {
			req.Content = response
		}
	case "postinvocation":
		req.Direction = "tool_result"
		req.ToolName = "message"
		req.Content = antigravityExtractResponse(payload)
	case "stop":
		// Stop is a session-end marker. There's no prompt or tool
		// call to inspect, but session metadata + an optional stop
		// reason are valuable for the audit envelope and any
		// SIEM-side correlation rules. Direction stays empty so the
		// unified evaluator's classifier dispatch falls to default
		// (allow + audit-only emission), which is the correct
		// behavior for a terminal lifecycle event.
		req.ToolName = "session"
		req.Content = antigravityExtractStopReason(payload)
	default:
		// Unknown / unrecognised event name. Treat as a tool call
		// for safety so any tool-call inspection still runs against
		// the payload; if no toolCall field is present this becomes
		// an effective no-op and the unified handler emits an
		// audit-only row.
		req.Direction = "tool_call"
		antigravityExtractToolCall(&req, payload)
	}

	if req.CWD == "" {
		req.CWD = antigravityFirstWorkspacePath(payload)
	}
	if req.ToolName == "" {
		req.ToolName = "tool"
	}

	return req
}

// antigravityCanonicalEvent normalises an event name (lowercase,
// strip underscores/dashes) for the decoder's per-event switch.
// Mirrors the gateway's canonicalEvent() helper so a future
// "Pre_Invocation" or "pre-invocation" variant routes to the same
// branch as the spec'd "PreInvocation" without code duplication.
func antigravityCanonicalEvent(event string) string {
	event = strings.ToLower(strings.TrimSpace(event))
	event = strings.ReplaceAll(event, "_", "")
	event = strings.ReplaceAll(event, "-", "")
	return event
}

// antigravityInferEvent picks a sensible default event name when
// the payload omits the explicit hookEventName field. Used for
// backward compat with agy v1.0.x payloads that predate the
// spec'd field. Inference precedence:
//
//  1. toolCall + toolResponse  → PostToolUse
//  2. toolCall                 → PreToolUse
//  3. modelResponse / response → PostInvocation
//  4. prompt / userMessage     → PreInvocation
//  5. fallback                 → PreToolUse (matches v1.0.x default)
//
// Never inferred: Stop. agy's Stop hook is expected to set the
// explicit hookEventName field per the spec; lacking that, we'd
// rather route an unrecognised payload to PreToolUse (where
// downstream inspection is harmless) than swallow it as a Stop
// event with no inspection.
func antigravityInferEvent(payload map[string]interface{}) string {
	if _, ok := antigravityObject(payload, "toolCall", "tool_call"); ok {
		if _, ok := antigravityObject(payload,
			"toolResponse", "tool_response",
			"toolResult", "tool_result",
		); ok {
			return "PostToolUse"
		}
		return "PreToolUse"
	}
	if hookFirstString(payload,
		"modelResponse", "model_response",
		"response", "modelOutput", "model_output",
	) != "" {
		return "PostInvocation"
	}
	if hookFirstString(payload,
		"prompt", "userPrompt", "user_prompt",
		"userMessage", "user_message",
	) != "" {
		return "PreInvocation"
	}
	return "PreToolUse"
}

// antigravityExtractToolCall lifts the nested toolCall descriptor
// onto the canonical request fields. Shared by PreToolUse and
// PostToolUse branches; both events carry the toolCall in identical
// shape (PostToolUse adds a toolResponse field at the top level).
func antigravityExtractToolCall(req *HookProfileRequest, payload map[string]interface{}) {
	toolCall, ok := antigravityObject(payload, "toolCall", "tool_call")
	if !ok {
		return
	}
	req.ToolName = hookFirstString(toolCall, "name", "tool_name", "toolName")
	args, ok := antigravityObject(toolCall,
		"args", "arguments",
		"tool_input", "toolInput",
	)
	if !ok {
		return
	}
	// Run_command-style tools surface Cwd + CommandLine. Generalised
	// key lookups so future tools (write_file, read_file, etc.)
	// project their primary string field onto Content for audit /
	// judge consumers without per-tool decoder branches.
	req.CWD = hookFirstString(args,
		"Cwd", "cwd",
		"working_directory", "workingDirectory",
	)
	req.Content = hookFirstString(args,
		"CommandLine", "command_line", "command",
		"prompt", "user_prompt",
		"input", "text",
	)
}

// antigravityExtractPrompt pulls the user prompt or system message
// from a PreInvocation payload. The 2.0 spec lists "Dynamically
// injecting context, modifying system instructions, or feeding
// custom workspace rules" as PreInvocation use cases — the prompt
// content is the inspection target for prompt-content rules.
//
// Field-name precedence walks the most-specific shape first
// (`prompt`) before falling back to chat-style messages arrays.
// Empty return is acceptable: the unified evaluator handles
// empty-content prompts as observe-only audit rows.
func antigravityExtractPrompt(payload map[string]interface{}) string {
	if s := hookFirstString(payload,
		"prompt", "userPrompt", "user_prompt",
		"userMessage", "user_message", "message",
		"systemInstruction", "system_instruction",
	); s != "" {
		return s
	}
	// Fall back to a Gemini-style messages array if present. Joins
	// content fields with a blank-line separator so multi-turn
	// transcripts are inspectable in a single Content blob.
	msgs, ok := payload["messages"].([]interface{})
	if !ok {
		return ""
	}
	var sb strings.Builder
	for _, m := range msgs {
		obj, ok := m.(map[string]interface{})
		if !ok {
			continue
		}
		if c := hookFirstString(obj, "content", "text"); c != "" {
			if sb.Len() > 0 {
				sb.WriteString("\n\n")
			}
			sb.WriteString(c)
		}
	}
	return sb.String()
}

// antigravityExtractToolResponse pulls the tool output from a
// PostToolUse payload. agy may nest the output under
// `toolResponse.output` (the most likely shape, mirroring its
// PreToolUse `toolCall.args` nesting) or flatten it at the top
// level for legacy compatibility. We try both.
func antigravityExtractToolResponse(payload map[string]interface{}) string {
	if resp, ok := antigravityObject(payload,
		"toolResponse", "tool_response",
		"toolResult", "tool_result",
	); ok {
		if s := hookFirstString(resp,
			"output", "stdout", "text", "content",
			"result", "error",
		); s != "" {
			return s
		}
	}
	return hookFirstString(payload,
		"output", "stdout", "result", "error",
	)
}

// antigravityExtractResponse pulls the LLM's generated response
// from a PostInvocation payload. Per the 2.0 spec, PostInvocation
// fires "after the LLM invocation completes and all associated
// tool calls have finished running" — the response content is
// the inspection target for output-content rules (PII leakage,
// secret echoing, etc.).
func antigravityExtractResponse(payload map[string]interface{}) string {
	if s := hookFirstString(payload,
		"modelResponse", "model_response", "response",
		"modelOutput", "model_output", "output",
		"text", "content",
	); s != "" {
		return s
	}
	if obj, ok := antigravityObject(payload,
		"modelResponse", "model_response",
		"response",
	); ok {
		if s := hookFirstString(obj, "text", "content", "output"); s != "" {
			return s
		}
	}
	return ""
}

// antigravityExtractStopReason pulls a brief description of why
// the agent loop is terminating from a Stop payload. Per the 2.0
// spec, Stop fires "when the agent's main execution loop is about
// to terminate" — we capture whatever stop reason agy ships for
// the audit envelope and any SIEM correlation rules.
//
// Empty return is acceptable: agy may simply terminate without
// emitting a structured stop reason, in which case the Stop event
// audit row carries only session metadata.
func antigravityExtractStopReason(payload map[string]interface{}) string {
	return hookFirstString(payload,
		"stopReason", "stop_reason",
		"reason", "finalState", "final_state",
		"status",
	)
}

// antigravityObject extracts the first key that resolves to a JSON
// object. Mirrors the lookahead the codex / claudecode profile
// decoders perform inline; pulled out so the keypath fallback list
// (camelCase + snake_case) stays declarative and the rest of the
// decoder reads top-down.
func antigravityObject(parent map[string]interface{}, keys ...string) (map[string]interface{}, bool) {
	for _, key := range keys {
		v, ok := parent[key]
		if !ok || v == nil {
			continue
		}
		if obj, ok := v.(map[string]interface{}); ok {
			return obj, true
		}
	}
	return nil, false
}

// antigravityFirstWorkspacePath returns the first non-empty string
// from payload.workspacePaths (or workspace_paths). agy ships the
// project root list as []string; we use the first entry as a
// best-effort CWD fallback when toolCall.args.Cwd is absent.
func antigravityFirstWorkspacePath(payload map[string]interface{}) string {
	for _, key := range []string{"workspacePaths", "workspace_paths"} {
		v, ok := payload[key]
		if !ok || v == nil {
			continue
		}
		arr, ok := v.([]interface{})
		if !ok {
			continue
		}
		for _, entry := range arr {
			if s, ok := entry.(string); ok {
				if trimmed := strings.TrimSpace(s); trimmed != "" {
					return trimmed
				}
			}
		}
	}
	return ""
}
