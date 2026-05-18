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

// claudeCodeProfileDecode implements HookProfile.Decode for Claude
// Code. Like codexProfileDecode, this is declarative for PR 5 /
// Phase C — handleClaudeCodeHook still owns dispatch — but the
// shape mirrors how PR 6 will fold the bespoke path into
// handleAgentHook so we can land it without a wire-format change.
func claudeCodeProfileDecode(payload map[string]interface{}) HookProfileRequest {
	req := HookProfileRequest{
		ConnectorName: "claudecode",
		HookEventName: hookFirstString(payload, "hook_event_name", "hookEventName"),
		SessionID:     hookFirstString(payload, "session_id", "sessionId"),
		AgentID:       hookFirstString(payload, "agent_id", "agentId"),
		AgentType:     hookFirstString(payload, "agent_type", "agentType"),
		CWD:           hookFirstString(payload, "cwd"),
		Model:         hookFirstString(payload, "model"),
		ToolName:      hookFirstString(payload, "tool_name", "toolName"),
		Content:       hookFirstString(payload, "prompt"),
		Payload:       payload,
	}
	if req.AgentType != "" && req.AgentName == "" {
		req.AgentName = req.AgentType
	}
	if req.AgentName == "" {
		req.AgentName = "claudecode"
	}
	switch req.HookEventName {
	case "UserPromptSubmit", "UserPromptExpansion":
		req.Direction = "prompt"
	case "PostToolUse", "PostToolUseFailure", "PostToolBatch":
		req.Direction = "tool_result"
	default:
		req.Direction = "tool_call"
	}
	return req
}

// claudeCodeProfileMapVerdict implements HookProfile.MapVerdict for
// Claude Code. Mirrors the inline mode-mapping in
// evaluateClaudeCodeHook:
//
//   - rawAction=="block" + event-is-not-claude-enforceable →
//     allow + wouldBlock=true (Claude Code's PostToolUseFailure,
//     SessionStart, etc. are observe-only by contract).
//   - observe mode: any block/alert/confirm verdict demotes to
//     allow; wouldBlock=true for the block case.
//   - action mode + rawAction=="confirm": stays confirm only on
//     PreToolUse (the one event that surfaces a native ask);
//     elsewhere demotes to alert.
func claudeCodeProfileMapVerdict(in HookVerdictInput) HookVerdictOutput {
	raw := normalizedGuardrailAction(in.RawAction)
	if raw == "" {
		raw = "allow"
	}

	if raw == "block" && !claudeCodeCanEnforceProfile(in.Event) {
		return HookVerdictOutput{Action: "allow", WouldBlock: true}
	}

	if in.Mode != "action" {
		return HookVerdictOutput{Action: "allow", WouldBlock: raw == "block"}
	}

	switch raw {
	case "block":
		return HookVerdictOutput{Action: "block", WouldBlock: false}
	case "confirm":
		if in.Caps.CanAskNative && eventInProfile(in.Event, in.Caps.AskEvents) {
			return HookVerdictOutput{Action: "confirm", WouldBlock: false}
		}
		return HookVerdictOutput{Action: "alert", WouldBlock: false}
	default:
		return HookVerdictOutput{Action: raw, WouldBlock: false}
	}
}

// claudeCodeProfileRespond implements HookProfile.Respond for Claude
// Code. Returns "claude_code_output" so the wire matches
// claudeCodeHookResponse exactly. Wire contract MUST match
// claudeCodeOutput() in gateway/claude_code_hook.go.
func claudeCodeProfileRespond(in HookRespondInput) HookRespondOutput {
	output := claudeCodeOutputForProfile(in.Req, in.Action, in.RawAction, in.Reason, in.AdditionalContext)
	return HookRespondOutput{FieldName: "claude_code_output", Output: output}
}

// claudeCodeOutputForProfile mirrors claudeCodeOutput() in
// gateway/claude_code_hook.go. Duplicated (not imported) because the
// connector package cannot depend on gateway. PR 7 cleanup deletes
// the gateway-side helper after PR 6 makes profile.Respond the
// authoritative path.
func claudeCodeOutputForProfile(req HookProfileRequest, action, rawAction, reason, additional string) map[string]interface{} {
	event := req.HookEventName
	if action == "confirm" && event == "PreToolUse" {
		return map[string]interface{}{"hookSpecificOutput": map[string]interface{}{
			"hookEventName":            "PreToolUse",
			"permissionDecision":       "ask",
			"permissionDecisionReason": claudeCodeReasonOrDefault(reason),
		}}
	}
	if action == "block" {
		switch event {
		case "PreToolUse":
			return map[string]interface{}{"hookSpecificOutput": map[string]interface{}{
				"hookEventName":            "PreToolUse",
				"permissionDecision":       "deny",
				"permissionDecisionReason": claudeCodeReasonOrDefault(reason),
			}}
		case "PermissionRequest":
			return map[string]interface{}{"hookSpecificOutput": map[string]interface{}{
				"hookEventName": "PermissionRequest",
				"decision": map[string]interface{}{
					"behavior": "deny",
					"message":  claudeCodeReasonOrDefault(reason),
				},
			}}
		case "TaskCreated", "TaskCompleted", "TeammateIdle":
			return map[string]interface{}{"continue": false, "stopReason": claudeCodeReasonOrDefault(reason)}
		case "Elicitation":
			return map[string]interface{}{"hookSpecificOutput": map[string]interface{}{
				"hookEventName": "Elicitation",
				"action":        "decline",
				"content":       map[string]interface{}{},
			}}
		case "ElicitationResult":
			return map[string]interface{}{"hookSpecificOutput": map[string]interface{}{
				"hookEventName": "ElicitationResult",
				"action":        "decline",
				"content":       map[string]interface{}{},
			}}
		default:
			return map[string]interface{}{"decision": "block", "reason": claudeCodeReasonOrDefault(reason)}
		}
	}
	// CwdChanged / FileChanged: PR 5 keeps watchPaths derivation in
	// the gateway (it consults req.NewCWD which is connector-specific
	// and not in HookProfileRequest yet). Until PR 6 widens
	// HookProfileRequest, the unified path falls back to nil here and
	// the legacy handler keeps producing watchPaths.
	if additional == "" {
		return nil
	}
	switch event {
	case "SessionStart", "UserPromptSubmit", "UserPromptExpansion", "PostToolUse", "PostToolUseFailure",
		"PostToolBatch", "Notification", "SubagentStart", "SubagentStop":
		return map[string]interface{}{"hookSpecificOutput": map[string]interface{}{
			"hookEventName":     event,
			"additionalContext": additional,
		}}
	case "CwdChanged":
		return map[string]interface{}{"watchPaths": []string{}}
	default:
		return map[string]interface{}{"systemMessage": additional}
	}
}

func claudeCodeReasonOrDefault(reason string) string {
	if strings.TrimSpace(reason) == "" {
		return "Blocked by DefenseClaw Claude Code policy."
	}
	return reason
}

// claudeCodeAdditionalContextForProfile mirrors
// claudeCodeAdditionalContext() in gateway/claude_code_hook.go. See
// codexAdditionalContextForProfile for the duplication rationale.
func claudeCodeAdditionalContextForProfile(rawAction, severity, reason string, wouldBlock bool) string {
	if rawAction == "allow" || rawAction == "" {
		return ""
	}
	prefix := "DefenseClaw observed"
	if wouldBlock {
		prefix = "DefenseClaw would block this in action mode"
	}
	if reason == "" {
		return fmt.Sprintf("%s a %s Claude Code hook finding.", prefix, severity)
	}
	return fmt.Sprintf("%s a %s Claude Code hook finding: %s", prefix, severity, reason)
}

// claudeCodeCanEnforceProfile mirrors claudeCodeCanEnforce() in
// gateway/claude_code_hook.go — the set of events for which a
// "block" verdict actually reaches an enforceable surface. Events
// outside this set produce wouldBlock=true / allow.
func claudeCodeCanEnforceProfile(event string) bool {
	switch event {
	case "UserPromptSubmit", "UserPromptExpansion", "PreToolUse", "PermissionRequest", "PostToolUse",
		"PostToolBatch", "TaskCreated", "TaskCompleted", "Stop", "SubagentStop", "TeammateIdle",
		"ConfigChange", "PreCompact", "Elicitation", "ElicitationResult":
		return true
	default:
		return false
	}
}
