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

// codexProfileDecode implements HookProfile.Decode for codex. It
// pulls the typed fields out of the raw payload and stashes them on
// a HookProfileRequest the unified collector can consume.
//
// Today (post PR #284) the unified gateway handler decodes the raw
// bytes into both an agentHookRequest (for the shared pipeline) and
// a codexHookRequest (for the bespoke evaluator, via
// bespoke_hook_adapter.go); this decoder is kept as the
// connector-side declarative shape so downstream consumers
// (out-of-tree gateways, future plugin-host clients) can read the
// canonical field map without depending on the gateway-side bespoke
// types.
func codexProfileDecode(payload map[string]interface{}) HookProfileRequest {
	req := HookProfileRequest{
		ConnectorName: "codex",
		HookEventName: hookFirstString(payload, "hook_event_name", "hookEventName"),
		SessionID:     hookFirstString(payload, "session_id", "sessionId"),
		TurnID:        hookFirstString(payload, "turn_id", "turnId"),
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
		req.AgentName = "codex"
	}
	// Direction inference matches normalizeAgentHookRequest's switch:
	// prompt-shaped events (UserPromptSubmit) → "prompt"; result-shaped
	// (PostToolUse) → "tool_result"; otherwise "tool_call". The unified
	// handler does NOT consult this field today — it's populated so
	// PR 6's unified evaluator can branch without re-deriving the
	// classification.
	switch req.HookEventName {
	case "UserPromptSubmit":
		req.Direction = "prompt"
	case "PostToolUse":
		req.Direction = "tool_result"
	default:
		req.Direction = "tool_call"
	}
	return req
}

// normalizedGuardrailAction canonicalizes an upstream verdict
// action string for the connector-package profile callbacks. Mirrors
// gateway/decision.go::normalizedGuardrailAction byte-for-byte —
// kept duplicated because the connector package cannot depend on
// gateway. PR 7 cleanup eliminates one of the two once dispatch is
// fully unified.
func normalizedGuardrailAction(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "block", "deny":
		return "block"
	case "confirm", "ask":
		return "confirm"
	case "alert", "warn", "warning":
		return "alert"
	default:
		return "allow"
	}
}

// codexProfileMapVerdict implements HookProfile.MapVerdict for codex.
// Mirrors the inline mode-mapping in evaluateCodexHook:
//
//   - observe mode: any block/alert/confirm verdict is demoted to
//     allow; wouldBlock=true for the block case so dashboards count
//     observe-mode catches.
//   - action mode: block stays block; confirm demotes to alert because
//     codex's PreToolUse only honors permission decisions deny/ask/allow
//     (we route the confirm via systemMessage instead — Respond handles
//     that shaping).
//
// Codex's CanBlock surface is restricted to {UserPromptSubmit,
// PreToolUse, PermissionRequest, PostToolUse, Stop} via
// HookCapabilities; the in.Caps.BlockEvents check protects against
// us telling codex to block on an event it cannot honor.
func codexProfileMapVerdict(in HookVerdictInput) HookVerdictOutput {
	raw := normalizedGuardrailAction(in.RawAction)
	if raw == "" {
		raw = "allow"
	}
	if in.Mode != "action" {
		// observe / inherit-with-observe / unknown all behave the
		// same: the agent is never told to block, but wouldBlock
		// captures the "we would have" signal.
		return HookVerdictOutput{Action: "allow", WouldBlock: raw == "block"}
	}
	switch raw {
	case "block":
		if !in.Caps.CanBlock || !eventInProfile(in.Event, in.Caps.BlockEvents) {
			return HookVerdictOutput{Action: "allow", WouldBlock: true}
		}
		return HookVerdictOutput{Action: "block", WouldBlock: false}
	case "confirm":
		// Codex has no native chat-side ask (CanAskNative=false), so
		// confirm always demotes to alert + systemMessage in Respond.
		return HookVerdictOutput{Action: "alert", WouldBlock: false}
	default:
		return HookVerdictOutput{Action: raw, WouldBlock: false}
	}
}

// codexProfileRespond implements HookProfile.Respond for codex. The
// returned FieldName is "codex_output" so the wire format matches
// codexHookResponse exactly (omitempty kicks in when Output is nil).
//
// The body shape is sourced from the same set of cases the bespoke
// codexOutput() helper in gateway/codex_hook.go produces. Keeping
// the two helpers byte-identical is asserted by
// TestUnifiedHookProfileRespond_CodexParity in PR 5's test suite.
func codexProfileRespond(in HookRespondInput) HookRespondOutput {
	output := codexOutputForProfile(in.Req.HookEventName, in.Action, in.RawAction, in.Reason, in.AdditionalContext)
	return HookRespondOutput{FieldName: "codex_output", Output: output}
}

// codexOutputForProfile is the connector-package mirror of the
// gateway's codexOutput() helper. Duplicated (not imported) because
// the gateway → connector dependency is one-directional; once PR 6
// has soaked, the gateway-side helper can be deleted and the
// gateway can call this through profile.Respond exclusively.
//
// Wire contract MUST match codexOutput() in gateway/codex_hook.go:
// any divergence breaks the PR-5 parity tests and ships a silent
// behavior regression for codex operators.
func codexOutputForProfile(event, action, rawAction, reason, additional string) map[string]interface{} {
	if action == "block" {
		switch event {
		case "PreToolUse":
			return map[string]interface{}{
				"hookSpecificOutput": map[string]interface{}{
					"hookEventName":            "PreToolUse",
					"permissionDecision":       "deny",
					"permissionDecisionReason": codexReasonOrDefault(reason),
				},
			}
		case "PermissionRequest":
			return map[string]interface{}{
				"hookSpecificOutput": map[string]interface{}{
					"hookEventName": "PermissionRequest",
					"decision": map[string]interface{}{
						"behavior": "deny",
						"message":  codexReasonOrDefault(reason),
					},
				},
			}
		case "UserPromptSubmit", "PostToolUse", "Stop":
			out := map[string]interface{}{
				"decision": "block",
				"reason":   codexReasonOrDefault(reason),
			}
			if event == "PostToolUse" && additional != "" {
				out["hookSpecificOutput"] = map[string]interface{}{
					"hookEventName":     "PostToolUse",
					"additionalContext": additional,
				}
			}
			return out
		}
	}

	if rawAction == "confirm" {
		if additional == "" {
			additional = "DefenseClaw wants user confirmation for this action."
		}
		switch event {
		case "PermissionRequest", "PreToolUse":
			return map[string]interface{}{"systemMessage": additional}
		}
	}

	if event == "Stop" {
		return map[string]interface{}{"continue": true}
	}
	if additional == "" {
		return nil
	}
	switch event {
	case "SessionStart":
		return map[string]interface{}{"systemMessage": additional}
	case "UserPromptSubmit", "PostToolUse":
		return map[string]interface{}{
			"hookSpecificOutput": map[string]interface{}{
				"hookEventName":     event,
				"additionalContext": additional,
			},
		}
	case "PreToolUse":
		return map[string]interface{}{"systemMessage": additional}
	default:
		return nil
	}
}

func codexReasonOrDefault(reason string) string {
	if strings.TrimSpace(reason) == "" {
		return "Blocked by DefenseClaw Codex policy."
	}
	return reason
}

// codexAdditionalContextForProfile is the connector-package mirror
// of the gateway's codexAdditionalContext() helper, exposed so the
// unified collector can construct the additional-context string
// before calling profile.Respond. Kept format-compatible with the
// bespoke handler so JSONEq fixtures pass under both flag states.
func codexAdditionalContextForProfile(rawAction, severity, reason string, wouldBlock bool) string {
	if rawAction == "allow" || rawAction == "" {
		return ""
	}
	prefix := "DefenseClaw observed"
	if wouldBlock {
		prefix = "DefenseClaw would block this in action mode"
	}
	if reason == "" {
		return fmt.Sprintf("%s a %s Codex hook finding.", prefix, severity)
	}
	return fmt.Sprintf("%s a %s Codex hook finding: %s", prefix, severity, reason)
}

// hookFirstString returns the first non-empty stringified value among
// the supplied keys. Mirrors agent_hook.go::firstString but lives in
// the connector package so the profile decoders can be self-contained
// (the gateway can't be a dependency of the connector package).
func hookFirstString(obj map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		v, ok := obj[key]
		if !ok || v == nil {
			continue
		}
		switch x := v.(type) {
		case string:
			if s := strings.TrimSpace(x); s != "" {
				return s
			}
		case fmt.Stringer:
			if s := strings.TrimSpace(x.String()); s != "" {
				return s
			}
		}
	}
	return ""
}

// eventInProfile mirrors agent_hook.go::eventIn but lives in the
// connector package. Both sides apply the same canonicalization
// (lowercase + strip _-) so a profile MapVerdict and the gateway's
// generic mapping agree on equality classes like
// "PreToolUse" == "pre_tool_use".
func eventInProfile(event string, events []string) bool {
	canon := canonicalHookEvent(event)
	for _, candidate := range events {
		if canonicalHookEvent(candidate) == canon {
			return true
		}
	}
	return false
}

func canonicalHookEvent(event string) string {
	event = strings.ToLower(strings.TrimSpace(event))
	event = strings.ReplaceAll(event, "_", "")
	event = strings.ReplaceAll(event, "-", "")
	return event
}
