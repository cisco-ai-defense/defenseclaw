// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// malformedHookPayloadReason validates the event envelope before any decoder
// can turn a malformed field into an empty or inferred event. A rejected
// request gets a connector-hook audit row, and a native managed hook answers
// the gateway's 400 with its closed failure verdict.
func malformedHookPayloadReason(connector string, raw []byte, payload map[string]interface{}, registeredEvent string) string {
	event, reason := hookEventEnvelope(payload)
	if reason != "" {
		return reason
	}
	if event == "" && strings.TrimSpace(registeredEvent) == "" {
		return "missing_event"
	}
	if event != "" && strings.TrimSpace(registeredEvent) != "" && event != strings.TrimSpace(registeredEvent) &&
		connector != "antigravity" && connector != "copilot" {
		// Antigravity and Copilot bind the event in the installed command;
		// their stdin event label is advisory. Keep the trusted bound event
		// so a body claiming a post-tool event cannot skip pre-tool review.
		// Codex checks exact agreement with its installer binding earlier.
		return "conflicting_event"
	}
	if event == "" {
		event = strings.TrimSpace(registeredEvent)
	}
	if !hookToolCallJSONUnambiguous(connector, raw) && !isGenericToolInspectionEvent(event) {
		// A structured pre-tool event is still accepted into the existing
		// unread-tool path, which returns a native deny and a hook_decision
		// with HOOK-TOOL-CALL-UNPARSED. Other malformed events have no
		// such safe decision path and get an audited rejection.
		return "ambiguous_json"
	}
	return ""
}

// The bound event checks run before full normalization for some connectors.
// Validate the decoded fields first so a wrong type cannot turn into an empty
// or inferred event and take an older gateway-error fail-mode path.
func hookEventEnvelope(payload map[string]interface{}) (string, string) {
	if payload == nil {
		return "", "invalid_json_object"
	}
	for _, key := range []string{"session_id", "sessionId", "conversation_id", "conversationId", "tool_name", "toolName", "hookName", "cwd"} {
		if value, present := payload[key]; present {
			if _, ok := value.(string); !ok {
				return "", "invalid_field_type"
			}
		}
	}
	var event string
	for _, key := range []string{"hook_event_name", "hookEventName", "event_type", "eventType", "event_name", "eventName", "agent_action_name", "event"} {
		value, present := payload[key]
		if !present {
			continue
		}
		name, ok := value.(string)
		name = strings.TrimSpace(name)
		if !ok || name == "" {
			return "", "invalid_event_type"
		}
		if event != "" && name != event {
			return "", "conflicting_event"
		}
		event = name
	}
	return event, ""
}

func preToolFieldsValid(payload map[string]interface{}) bool {
	var toolName string
	for _, key := range []string{"tool_name", "toolName"} {
		value, present := payload[key]
		if !present {
			continue
		}
		name, ok := value.(string)
		if !ok || strings.TrimSpace(name) == "" || toolName != "" && name != toolName {
			return false
		}
		toolName = name
	}
	if toolName == "" {
		return false
	}
	inputs := 0
	for _, key := range []string{"tool_input", "toolInput"} {
		value, present := payload[key]
		if !present {
			continue
		}
		if _, ok := value.(map[string]interface{}); !ok {
			return false
		}
		inputs++
	}
	return inputs == 1
}

func unparsedStructuredHookResponse(profile connector.HookProfile, req agentHookRequest) agentHookResponse {
	reason := unparsedToolCallReason(req.ConnectorName)
	resp := agentHookResponseForProfile(profile, req, "block", "block", "HIGH", reason,
		[]string{hookToolCallUnparsedRuleID}, "action", false, profile.Capabilities)
	resp.RuleIDs = []string{hookToolCallUnparsedRuleID}
	return resp
}
