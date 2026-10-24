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

import "strings"

// claudeCodeProfileDecode implements HookProfile.Decode for Claude
// Code. Today (post PR #284) the unified gateway handler decodes
// the raw bytes into both an agentHookRequest (for the shared
// pipeline) and a claudeCodeHookRequest (for the profile-runtime
// evaluator); this decoder is kept as the connector-side declarative
// shape so downstream consumers (out-of-tree gateways, future
// plugin-host clients) can read the canonical field map without
// depending on the gateway-side typed request.
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
	case "MessageDisplay":
		req.Content = hookFirstString(payload, "delta")
		req.Direction = "response"
	case "StopFailure":
		req.Content = strings.Join(hookNonEmptyStrings(
			hookFirstString(payload, "error"),
			hookFirstString(payload, "error_details", "errorDetails"),
		), "\n")
		req.Direction = "tool_result"
	case "SubagentStart", "CwdChanged", "DirectoryAdded", "WorktreeRemove", "TaskCreated",
		"TaskCompleted", "TeammateIdle", "PreCompact", "PostCompact",
		"Elicitation", "ElicitationResult", "Notification":
		req.Content = claudeCodeProfileEventContent(payload)
		req.Direction = "event_content"
	default:
		req.Direction = "tool_call"
	}
	return req
}

func hookNonEmptyStrings(values ...string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, value)
		}
	}
	return out
}

func claudeCodeProfileEventContent(payload map[string]interface{}) string {
	return strings.Join(hookNonEmptyStrings(
		hookFirstString(payload, "message"),
		hookFirstString(payload, "title"),
		hookFirstString(payload, "file_path", "filePath"),
		hookFirstString(payload, "source"),
		hookFirstString(payload, "load_reason", "loadReason"),
		hookFirstString(payload, "memory_type", "memoryType"),
		hookFirstString(payload, "mcp_server_name", "mcpServerName"),
		hookFirstString(payload, "action"),
		hookFirstString(payload, "url"),
		hookFirstString(payload, "agent_id", "agentId"),
		hookFirstString(payload, "agent_type", "agentType"),
		hookFirstString(payload, "old_cwd", "oldCwd"),
		hookFirstString(payload, "new_cwd", "newCwd"),
		hookFirstString(payload, "directory"),
		hookFirstString(payload, "worktree_path", "worktreePath"),
		hookFirstString(payload, "last_assistant_message", "lastAssistantMessage"),
		hookFirstString(payload, "content"),
		hookFirstString(payload, "compact_summary", "compactSummary"),
		hookFirstString(payload, "custom_instructions", "customInstructions"),
		hookFirstString(payload, "task_subject", "taskSubject"),
		hookFirstString(payload, "task_description", "taskDescription"),
		hookFirstString(payload, "reason"),
	), "\n")
}

// claudeCodeProfileMapVerdict implements HookProfile.MapVerdict for
// Claude Code. Mirrors the inline mode-mapping in
// evaluateClaudeCodeHook:
//
//   - rawAction=="block" + event-is-not-claude-enforceable →
//     allow + wouldBlock=true (Claude Code's PostToolUse,
//     PostToolBatch, SessionStart, etc. are observe-only by contract).
//   - observe mode: any block/alert/confirm verdict demotes to
//     allow; wouldBlock=true for the block case.
//   - action mode + rawAction=="confirm": stays confirm only on
//     PreToolUse (the one event that surfaces a native ask) in a
//     permission mode that shows the ask, and blocks in any other
//     mode (ClaudeCodeModeCanAsk);
//     elsewhere demotes to alert.
func claudeCodeProfileMapVerdict(in HookVerdictInput) HookVerdictOutput {
	raw := normalizedGuardrailAction(in.RawAction)
	if raw == "" {
		raw = "allow"
	}

	if raw == "block" && !claudeCodeCanEnforceProfile(in) {
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
			if in.Event == "PreToolUse" && !ClaudeCodeModeCanAsk(hookFirstString(in.Payload, "permission_mode", "permissionMode")) {
				return HookVerdictOutput{Action: "block", WouldBlock: false}
			}
			return HookVerdictOutput{Action: "confirm", WouldBlock: false}
		}
		return HookVerdictOutput{Action: "alert", WouldBlock: false}
	default:
		return HookVerdictOutput{Action: raw, WouldBlock: false}
	}
}

// ClaudeCodeModeCanAsk reports whether DefenseClaw sends a PreToolUse
// permissionDecision "ask" in the session's permission_mode. Only "default"
// (labeled Manual) is a mode where the ask reliably reaches the user. In
// acceptEdits, bypassPermissions and dontAsk Claude Code can treat "ask" as
// "defer", so allow rules or the mode decide and the call can run with no
// prompt; in auto the classifier can still deny it unshown, and plan does
// not run tools (code.claude.com/docs/en/hooks, PreToolUse decision
// control). Manual-only is DefenseClaw's policy: any other, missing or
// unknown mode fails closed to a block (GAP-0371).
func ClaudeCodeModeCanAsk(permissionMode string) bool {
	return strings.TrimSpace(permissionMode) == "default"
}

// ClaudeCodeNoAskReason adds the next step to the reason of a confirmation
// that was blocked because the session is not in Manual mode. It is
// idempotent, so each wire shaper may apply it.
func ClaudeCodeNoAskReason(reason, permissionMode string) string {
	mode := strings.TrimSpace(permissionMode)
	where := "this permission mode"
	if mode != "" {
		where = mode + " mode"
	}
	hint := "DefenseClaw asks for approval only in Claude Code's Manual mode, so it blocked the call in " + where +
		". To approve it, switch Claude Code to Manual mode (Shift+Tab) and ask again."
	reason = strings.TrimSpace(reason)
	if strings.Contains(reason, hint) {
		return reason
	}
	if reason == "" {
		return hint
	}
	return reason + " " + hint
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
// connector package cannot depend on gateway. Both are live: the
// gateway helper shapes the Claude Code evaluator's answer, and this one
// shapes the answer when the ordered-safety-rule merge raises the verdict
// (mergeAgentHookFindings), so a change to one must reach the other.
func claudeCodeOutputForProfile(req HookProfileRequest, action, rawAction, reason, additional string) map[string]interface{} {
	event := req.HookEventName
	if action == "confirm" && event == "PreToolUse" {
		return map[string]interface{}{"hookSpecificOutput": map[string]interface{}{
			"hookEventName":            "PreToolUse",
			"permissionDecision":       "ask",
			"permissionDecisionReason": claudeCodeReasonOrDefault(reason),
		}}
	}
	if action == "block" && event == "PreToolUse" && strings.EqualFold(strings.TrimSpace(rawAction), "confirm") {
		reason = ClaudeCodeNoAskReason(reason, hookFirstString(req.Payload, "permission_mode", "permissionMode"))
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
		case "SessionStart", "TaskCreated", "TaskCompleted", "TeammateIdle":
			// No structured output: hookexec must render the policy reason on
			// stderr and exit 2 so Claude applies the event-specific feedback.
			return nil
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
	watchRoot := strings.TrimSpace(hookFirstString(req.Payload, "new_cwd", "newCwd"))
	if watchRoot == "" {
		watchRoot = req.CWD
	}
	if event == "SessionStart" {
		output := map[string]interface{}{
			"hookEventName": "SessionStart",
			"watchPaths":    ClaudeCodeWatchPaths(watchRoot),
		}
		if additional != "" {
			output["additionalContext"] = additional
		}
		return map[string]interface{}{"hookSpecificOutput": output}
	}
	if event == "CwdChanged" || event == "FileChanged" {
		output := map[string]interface{}{"watchPaths": ClaudeCodeWatchPaths(watchRoot)}
		if additional != "" {
			output["systemMessage"] = additional
		}
		return output
	}
	if additional == "" {
		return nil
	}
	switch event {
	case "UserPromptSubmit", "UserPromptExpansion", "PostToolUse", "PostToolUseFailure",
		"PostToolBatch", "SubagentStart", "SubagentStop":
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

// claudeCodeCanEnforceProfile mirrors claudeCodeCanEnforce() in
// gateway/claude_code_hook.go — the set of events for which a
// "block" verdict actually reaches an enforceable surface. Events
// outside this set produce wouldBlock=true / allow.
func claudeCodeCanEnforceProfile(in HookVerdictInput) bool {
	if in.Event == "ConfigChange" && strings.EqualFold(strings.TrimSpace(hookFirstString(in.Payload, "source")), "policy_settings") {
		return false
	}
	return in.Caps.CanBlock && eventInProfile(in.Event, in.Caps.BlockEvents)
}
