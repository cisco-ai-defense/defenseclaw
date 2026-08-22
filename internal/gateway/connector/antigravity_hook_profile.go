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
	"encoding/json"
	"strings"
)

// antigravityProfileDecode maps Google's documented Antigravity hook stdin
// schemas onto the unified request. Antigravity does not include an event-name
// field in stdin. Setup binds each registration to `--event <Event>` and the
// hook bridge forwards that value out-of-band; handleAgentHook injects the
// trusted value as hookEventName before calling this decoder.
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
	toolCall, ok := antigravityObject(payload, "toolCall")
	if !ok {
		return
	}
	req.ToolName = hookFirstString(toolCall, "name")
	args, ok := antigravityObject(toolCall, "args")
	if !ok {
		return
	}
	if encoded, err := json.Marshal(args); err == nil {
		req.ToolArgs = encoded
	}
	req.CWD = hookFirstString(args, "Cwd", "cwd")
	req.Content = hookFirstString(args,
		"CommandLine", "commandLine", "command",
		"prompt", "input", "text",
	)
}

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
