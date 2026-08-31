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
	"strings"
)

// cursorProfileDecode projects Cursor's documented per-event payloads onto
// DefenseClaw's canonical inspection request. Cursor's specialized shell,
// MCP, and file hooks do not use the generic tool_name/tool_input pair:
// beforeShellExecution carries a top-level command, beforeMCPExecution carries
// JSON parameters as a string, and file hooks carry file_path/content/edits.
// Leaving those shapes to the generic decoder labels shell requests as "tool"
// and turns MCP parameters into a JSON string, which records findings but does
// not provide the typed, enforceable facts used by action mode.
//
// Cursor documents generation_id as the identifier for one user-message
// generation. Preserve that connector-native turn mapping here as well as in
// the shared CorrelationSpec so callers that use the profile decoder directly
// observe the same identity semantics. conversation_id remains owned by the
// shared normalizer.
func cursorProfileDecode(payload map[string]interface{}) HookProfileRequest {
	req := HookProfileRequest{
		ConnectorName: "cursor",
		HookEventName: hookFirstString(payload,
			"hook_event_name", "hookEventName",
			"event_type", "eventType",
			"event_name", "eventName",
			"agent_action_name",
		),
		TurnID: hookFirstString(payload,
			"generation_id", "generationId",
			"turn_id", "turnId", "turnID",
		),
		CWD:     hookFirstString(payload, "cwd", "working_directory", "workingDirectory"),
		Payload: payload,
	}

	switch canonicalHookEvent(req.HookEventName) {
	case "pretooluse":
		req.ToolName = hookFirstString(payload, "tool_name", "toolName")
		req.ToolArgs = cursorToolInput(cursorFirstValue(payload, "tool_input", "toolInput"))
		req.ToolArgsAuthoritative = true
	case "posttooluse":
		req.ToolName = hookFirstString(payload, "tool_name", "toolName")
		req.ToolArgs = cursorToolInput(cursorFirstValue(payload, "tool_input", "toolInput"))
		req.ToolArgsAuthoritative = true
		req.Content = hookFirstString(payload, "tool_output", "toolOutput")
		req.Direction = "tool_result"
	case "posttoolusefailure":
		req.ToolName = hookFirstString(payload, "tool_name", "toolName")
		req.ToolArgs = cursorToolInput(cursorFirstValue(payload, "tool_input", "toolInput"))
		req.ToolArgsAuthoritative = true
		req.Content = hookFirstString(payload, "error_message", "errorMessage")
		req.Direction = "tool_result"
	case "beforeshellexecution":
		req.ToolName = "Shell"
		// sandbox is Cursor execution-control metadata, not shell input. It
		// remains available in Payload for audit, but putting it in ToolArgs
		// would make the closed ActionFacts command schema intentionally partial.
		req.ToolArgs = cursorProjectedArgs(payload,
			cursorProjection{target: "command", sources: []string{"command"}},
			cursorProjection{target: "cwd", sources: []string{"cwd"}},
		)
		req.ToolArgsAuthoritative = true
	case "aftershellexecution":
		req.ToolName = "Shell"
		req.ToolArgs = cursorProjectedArgs(payload,
			cursorProjection{target: "command", sources: []string{"command"}},
			cursorProjection{target: "cwd", sources: []string{"cwd"}},
		)
		req.ToolArgsAuthoritative = true
		req.Content = hookFirstString(payload, "output")
		req.Direction = "tool_result"
	case "beforemcpexecution":
		req.ToolName = hookFirstString(payload, "tool_name", "toolName")
		req.ToolArgs = cursorToolInput(cursorFirstValue(payload, "tool_input", "toolInput"))
		req.ToolArgsAuthoritative = true
	case "aftermcpexecution":
		req.ToolName = hookFirstString(payload, "tool_name", "toolName")
		req.ToolArgs = cursorToolInput(cursorFirstValue(payload, "tool_input", "toolInput"))
		req.ToolArgsAuthoritative = true
		req.Content = hookFirstString(payload, "result_json", "resultJson")
		req.Direction = "tool_result"
	case "beforereadfile", "beforetabfileread":
		if canonicalHookEvent(req.HookEventName) == "beforetabfileread" {
			req.ToolName = "TabRead"
		} else {
			req.ToolName = "Read"
		}
		req.ToolArgs = cursorProjectedArgs(payload,
			cursorProjection{target: "path", sources: []string{"file_path", "filePath"}},
			cursorProjection{target: "file_path", sources: []string{"file_path", "filePath"}},
			cursorProjection{target: "content", sources: []string{"content"}},
			cursorProjection{target: "attachments", sources: []string{"attachments"}},
		)
		req.ToolArgsAuthoritative = true
	case "afterfileedit", "aftertabfileedit":
		if canonicalHookEvent(req.HookEventName) == "aftertabfileedit" {
			req.ToolName = "TabWrite"
		} else {
			req.ToolName = "Write"
		}
		req.ToolArgs = cursorProjectedArgs(payload,
			cursorProjection{target: "path", sources: []string{"file_path", "filePath"}},
			cursorProjection{target: "file_path", sources: []string{"file_path", "filePath"}},
			cursorProjection{target: "edits", sources: []string{"edits"}},
		)
		req.ToolArgsAuthoritative = true
		req.Content = cursorJSONString(cursorFirstValue(payload, "edits"))
		req.Direction = "tool_result"
	case "beforesubmitprompt":
		req.ToolName = "message"
		req.Content = hookFirstString(payload, "prompt")
		req.Direction = "prompt"
	case "subagentstart":
		req.ToolName = "Task"
		req.Content = hookFirstString(payload, "task")
		req.Direction = "prompt"
	case "subagentstop":
		req.ToolName = "Task"
		req.Content = hookFirstString(payload, "summary", "error_message", "errorMessage")
		req.Direction = "tool_result"
	case "afteragentresponse", "afteragentthought":
		req.ToolName = "message"
		req.Content = hookFirstString(payload, "text")
		req.Direction = "tool_result"
	}

	return req
}

type cursorProjection struct {
	target  string
	sources []string
}

func cursorProjectedArgs(payload map[string]interface{}, fields ...cursorProjection) json.RawMessage {
	projected := make(map[string]interface{}, len(fields))
	for _, field := range fields {
		value := cursorFirstValue(payload, field.sources...)
		if value == nil {
			continue
		}
		// The Windows Cursor Agent currently emits cwd:"" for shell hooks.
		// CWD is optional context, not part of the command itself. Forwarding the
		// blank value would correctly make ActionFacts reject cwd as malformed,
		// but would also downgrade an otherwise complete, authoritative command
		// to detection-only. Omit only this blank optional field; keep blank
		// command, path, and content values so malformed action material remains
		// visible to the normal conservative parser.
		if field.target == "cwd" {
			if text, ok := value.(string); ok && strings.TrimSpace(text) == "" {
				continue
			}
		}
		projected[field.target] = value
	}
	return cursorJSON(projected)
}

func cursorFirstValue(payload map[string]interface{}, keys ...string) interface{} {
	for _, key := range keys {
		if value, ok := payload[key]; ok && value != nil {
			return value
		}
	}
	return nil
}

// Cursor documents MCP tool_input as a JSON params string, while preToolUse
// carries an object. Decode valid JSON strings so policy and MCP asset scanners
// receive the same typed map in both cases. Preserve malformed strings in a
// valid object so deterministic scanners can still inspect their exact text.
func cursorToolInput(value interface{}) json.RawMessage {
	if raw, ok := value.(string); ok {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			return json.RawMessage(`{}`)
		}
		candidate := []byte(trimmed)
		if json.Valid(candidate) {
			return append(json.RawMessage(nil), candidate...)
		}
		return cursorJSON(map[string]interface{}{"raw_input": raw})
	}
	if value == nil {
		return json.RawMessage(`{}`)
	}
	return cursorJSON(value)
}

func cursorJSONString(value interface{}) string {
	if value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return text
	}
	return string(cursorJSON(value))
}

func cursorJSON(value interface{}) json.RawMessage {
	encoded, err := json.Marshal(value)
	if err != nil || len(bytes.TrimSpace(encoded)) == 0 {
		return json.RawMessage(`{}`)
	}
	return json.RawMessage(encoded)
}
