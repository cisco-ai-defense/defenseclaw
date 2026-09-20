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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const antigravityMaxJSONNestingDepth = 64

// antigravityProfileDecode implements HookProfile.Decode for Google's
// Antigravity (`agy`) CLI / IDE. agy emits Claude-Code-derived hook
// payloads — fields are nested rather than flat — so the unified
// gateway decoder (normalizeAgentHookRequest) cannot extract event
// names or tool descriptors without a connector-specific decoder.
// Without this decoder, the unified handler returns HTTP 400
// ("hook event name is required") on every agy hook POST.
// Current Setup registrations bind each event out-of-band; that trusted
// registration remains authoritative over any payload event field.
//
// Official event inputs:
//   - all events: conversationId, workspacePaths, transcriptPath,
//     artifactDirectoryPath
//   - PreToolUse: toolCall{name,args}, stepIdx
//   - PostToolUse: stepIdx, error
//   - PreInvocation/PostInvocation: invocationNum, initialNumSteps
//   - Stop: executionNum, terminationReason, error, fullyIdle
//
// No Claude Code prompt, modelResponse, toolResponse, systemMessage, or
// additionalContext fields are inferred here.
func antigravityProfileDecode(payload map[string]interface{}) HookProfileRequest {
	req := HookProfileRequest{
		ConnectorName: "antigravity",
		AgentName:     "antigravity",
		AgentType:     "antigravity",
		Payload:       payload,
		SessionID: hookFirstString(payload,
			"conversationId",
		),
		HookEventName: hookFirstString(payload, "hookEventName"),
	}

	// Legacy DefenseClaw registrations had one eventless command and only
	// handled PreToolUse. Retain that narrow migration fallback; all current
	// registrations supply the event explicitly.
	if req.HookEventName == "" {
		if _, ok := antigravityObject(payload, "toolCall"); ok {
			req.HookEventName = "PreToolUse"
		}
	}

	switch antigravityCanonicalEvent(req.HookEventName) {
	case "pretooluse":
		req.Direction = "tool_call"
		antigravityExtractToolCall(&req, payload)
	case "posttooluse":
		req.Direction = "tool_result"
		req.ToolName = "tool"
		req.Content = hookFirstString(payload, "error")
	case "preinvocation", "postinvocation":
		// The official payload contains counters and common metadata only.
		// Preserve it for audit/correlation without inventing inspectable
		// prompt or model-output content.
		req.ToolName = "invocation"
	case "stop":
		req.ToolName = "session"
		req.Content = hookFirstString(payload, "terminationReason", "error")
	}

	req.CWD = antigravityFirstWorkspacePath(payload)
	if req.ToolName == "" {
		req.ToolName = "tool"
	}
	return req
}

func antigravityCanonicalEvent(event string) string {
	event = strings.ToLower(strings.TrimSpace(event))
	event = strings.ReplaceAll(event, "_", "")
	event = strings.ReplaceAll(event, "-", "")
	return event
}

func antigravityExtractToolCall(req *HookProfileRequest, payload map[string]interface{}) {
	// This profile owns the nested args projection. Mark it authoritative even
	// when extraction fails so the gateway never falls back to serializing the
	// complete, attacker-influenced payload as if it were tool arguments.
	req.ToolArgsAuthoritative = true
	toolCall, ok := antigravityUniqueObject(payload, "toolCall", "tool_call")
	if !ok {
		return
	}
	toolName, ok := antigravityUniqueString(toolCall, "name", "tool_name", "toolName")
	if !ok {
		return
	}
	req.ToolName = toolName
	args, ok := antigravityUniqueObject(toolCall,
		"args", "arguments",
		"tool_input", "toolInput",
	)
	if !ok {
		return
	}
	argBytes, err := json.Marshal(args)
	if err != nil {
		return
	}
	req.ToolArgs = json.RawMessage(argBytes)
	// Run_command-style tools surface Cwd + CommandLine. Generalised
	// key lookups so future tools (write_file, read_file, etc.)
	// project their primary string field onto Content for audit /
	// judge consumers without per-tool decoder branches.
	req.CWD = hookFirstString(args,
		"Cwd", "cwd",
		"working_directory", "workingDirectory",
	)
	req.Content = hookFirstString(args,
		"CommandLine", "commandLine", "command",
		"prompt", "input", "text",
	)
}

// antigravityToolArgsFromRawPayload returns the literal toolCall.args JSON
// object from the authenticated hook body. It rejects malformed JSON,
// duplicate JSON object keys, alias collisions, and non-object args. Those
// cases return nil so ambiguous input can never acquire structured authority
// from the generic payload-string fallback.
func antigravityToolArgsFromRawPayload(rawPayload []byte) json.RawMessage {
	if err := antigravityValidateUniqueJSON(rawPayload); err != nil {
		return nil
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(rawPayload, &payload); err != nil {
		return nil
	}
	toolCallRaw, ok := antigravityUniqueRawField(payload, "toolCall", "tool_call")
	if !ok || !antigravityRawJSONObject(toolCallRaw) {
		return nil
	}
	var toolCall map[string]json.RawMessage
	if err := json.Unmarshal(toolCallRaw, &toolCall); err != nil {
		return nil
	}
	nameRaw, ok := antigravityUniqueRawField(toolCall, "name", "tool_name", "toolName")
	if !ok {
		return nil
	}
	var toolName string
	if err := json.Unmarshal(nameRaw, &toolName); err != nil || strings.TrimSpace(toolName) == "" {
		return nil
	}
	argsRaw, ok := antigravityUniqueRawField(toolCall,
		"args", "arguments", "tool_input", "toolInput",
	)
	if !ok || !antigravityRawJSONObject(argsRaw) {
		return nil
	}
	return append(json.RawMessage(nil), argsRaw...)
}

func antigravityUniqueRawField(parent map[string]json.RawMessage, keys ...string) (json.RawMessage, bool) {
	var found json.RawMessage
	for _, key := range keys {
		value, ok := parent[key]
		if !ok {
			continue
		}
		if found != nil {
			return nil, false
		}
		found = value
	}
	return found, found != nil
}

func antigravityRawJSONObject(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) >= 2 && trimmed[0] == '{' && trimmed[len(trimmed)-1] == '}'
}

func antigravityValidateUniqueJSON(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := antigravityConsumeUniqueJSONValue(dec, 0); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}

func antigravityConsumeUniqueJSONValue(dec *json.Decoder, depth int) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if depth >= antigravityMaxJSONNestingDepth {
		return fmt.Errorf(
			"JSON nesting exceeds maximum depth of %d",
			antigravityMaxJSONNestingDepth,
		)
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON field %q", key)
			}
			seen[key] = struct{}{}
			if err := antigravityConsumeUniqueJSONValue(dec, depth+1); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return fmt.Errorf("invalid JSON object terminator")
		}
	case '[':
		for dec.More() {
			if err := antigravityConsumeUniqueJSONValue(dec, depth+1); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return fmt.Errorf("invalid JSON array terminator")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
	return nil
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
		value, ok := parent[key]
		if !ok || value == nil {
			continue
		}
		if object, ok := value.(map[string]interface{}); ok {
			return object, true
		}
	}
	return nil, false
}

func antigravityUniqueObject(parent map[string]interface{}, keys ...string) (map[string]interface{}, bool) {
	var found map[string]interface{}
	foundKey := false
	for _, key := range keys {
		value, ok := parent[key]
		if !ok {
			continue
		}
		if foundKey {
			return nil, false
		}
		foundKey = true
		object, ok := value.(map[string]interface{})
		if !ok {
			return nil, false
		}
		found = object
	}
	return found, foundKey
}

func antigravityUniqueString(parent map[string]interface{}, keys ...string) (string, bool) {
	var found string
	foundKey := false
	for _, key := range keys {
		value, ok := parent[key]
		if !ok {
			continue
		}
		if foundKey {
			return "", false
		}
		foundKey = true
		text, ok := value.(string)
		if !ok || strings.TrimSpace(text) == "" {
			return "", false
		}
		found = text
	}
	return found, foundKey
}

// antigravityFirstWorkspacePath returns the first non-empty string
// from payload.workspacePaths (or workspace_paths). agy ships the
// project root list as []string; we use the first entry as a
// best-effort CWD fallback when toolCall.args.Cwd is absent.
func antigravityFirstWorkspacePath(payload map[string]interface{}) string {
	value, ok := payload["workspacePaths"]
	if !ok {
		return ""
	}
	paths, ok := value.([]interface{})
	if !ok {
		return ""
	}
	for _, path := range paths {
		if text, ok := path.(string); ok {
			if trimmed := strings.TrimSpace(text); trimmed != "" {
				return trimmed
			}
		}
	}
	return ""
}
