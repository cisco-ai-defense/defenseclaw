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

// openHandsHookEvents maps the OpenHands SDK HookEventType values the CLI
// writes to a hook's stdin as event_type (openhands/sdk/hooks/types.py:
// PreToolUse, PostToolUse, ...) to the snake_case event keys of
// openhands-hooks-v1. Those keys are what hooks.json registers and what the
// contract's block events and tool-call lifecycle name. Passed through
// verbatim, a real CLI's PreToolUse matched none of them: the tool call was
// never routed as a structured action, so command rules never ran on it.
var openHandsHookEvents = map[string]string{
	"PreToolUse":       "pre_tool_use",
	"PostToolUse":      "post_tool_use",
	"UserPromptSubmit": "user_prompt_submit",
	"Stop":             "stop",
	"SessionStart":     "session_start",
	"SessionEnd":       "session_end",
}

// OpenHandsTrustedShellArgs projects the tool_input of an OpenHands terminal
// call (the SDK's TerminalAction: command, is_input, timeout, reset, kind)
// onto the {"command": ...} shell shape the trusted-action parser proves.
// With the extra fields left in, the parse is only partial, so no command
// rule could ever close its trusted-action proof and a CRITICAL finding
// stayed an allowed candidate.
//
// The projection is exact or refused (ok false, arguments unchanged): every
// key must be unique and known, the command a string, is_input and reset
// false or null (is_input sends the text to a running process instead of
// starting a command), timeout a number or null, kind "TerminalAction", and
// the model's security_risk and summary labels strings or null.
func OpenHandsTrustedShellArgs(toolName string, args json.RawMessage) (json.RawMessage, bool) {
	if strings.TrimSpace(toolName) != "terminal" || antigravityValidateUniqueJSON(args) != nil {
		return args, false
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(args, &fields); err != nil || fields == nil {
		return args, false
	}
	var command string
	if raw, ok := fields["command"]; !ok || json.Unmarshal(raw, &command) != nil {
		return args, false
	}
	for key, raw := range fields {
		switch key {
		case "command":
		case "is_input", "reset":
			var flag *bool
			if json.Unmarshal(raw, &flag) != nil || (flag != nil && *flag) {
				return args, false
			}
		case "timeout":
			var seconds *float64
			if json.Unmarshal(raw, &seconds) != nil {
				return args, false
			}
		case "kind":
			var kind string
			if json.Unmarshal(raw, &kind) != nil || kind != "TerminalAction" {
				return args, false
			}
		case "security_risk", "summary":
			var label *string
			if json.Unmarshal(raw, &label) != nil {
				return args, false
			}
		default:
			return args, false
		}
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(map[string]string{"command": command}); err != nil {
		return args, false
	}
	return bytes.TrimSuffix(out.Bytes(), []byte("\n")), true
}

// openHandsProfileDecode supplies only the contract event name; every other
// field keeps the generic decoding (tool_name, tool_input, working_dir).
func openHandsProfileDecode(payload map[string]interface{}) HookProfileRequest {
	req := HookProfileRequest{ConnectorName: "openhands"}
	if event, ok := payload["event_type"].(string); ok {
		if mapped, known := openHandsHookEvents[strings.TrimSpace(event)]; known {
			req.HookEventName = mapped
		}
	}
	return req
}
