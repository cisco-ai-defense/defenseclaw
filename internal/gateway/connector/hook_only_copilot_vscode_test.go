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
	"testing"
)

func TestCopilotVSCodeLocalProfile(t *testing.T) {
	p := CopilotVSCodeLocalProfile(NewCopilotConnector().HookProfile(SetupOpts{}))
	if err := ValidateToolCallLifecycleContract(p.ToolCallLifecycle, p.SupportedEvents); err != nil {
		t.Fatalf("lifecycle: %v", err)
	}
	if p.Correlation.Connector == "" {
		t.Fatal("no correlation spec for the Local dialect contract")
	}

	for _, tc := range []struct{ tool, input, want string }{
		{"run_in_terminal", `{"command":"ls","explanation":"x","isBackground":false}`, `{"command":"ls"}`},
		{"replace_string_in_file", `{"filePath":"/w/a","oldString":"a","newString":"b"}`, `{"content":"b","path":"/w/a"}`},
		{"fetch_webpage", `{"urls":["https://example.com"],"query":"q"}`, `{"url":"https://example.com"}`},
		// An argument outside the reviewed set keeps the native object.
		{"run_in_terminal", `{"command":"ls","cwd":"/tmp"}`, `{"command":"ls","cwd":"/tmp"}`},
		{"future_tool", `{"x":1}`, `{"x":1}`},
	} {
		var input map[string]interface{}
		if err := json.Unmarshal([]byte(tc.input), &input); err != nil {
			t.Fatal(err)
		}
		req := p.Decode(map[string]interface{}{
			"hook_event_name": "PreToolUse", "tool_name": tc.tool, "tool_input": input,
		})
		if string(req.ToolArgs) != tc.want || req.ToolName != tc.tool {
			t.Fatalf("%s %s: args=%s tool=%s, want %s", tc.tool, tc.input, req.ToolArgs, req.ToolName, tc.want)
		}
	}

	respond := func(event, action string) map[string]interface{} {
		return p.Respond(HookRespondInput{Req: HookProfileRequest{ConnectorName: "copilot", HookEventName: event}, Action: action}).Output
	}
	if out := respond("PreToolUse", "allow"); out != nil {
		t.Fatalf("allow rendered %v; a Local allow auto-approves the call", out)
	}
	if out := respond("PreToolUse", "confirm"); out["hookSpecificOutput"].(map[string]interface{})["permissionDecision"] != "ask" {
		t.Fatalf("confirm rendered %v", out)
	}
	if out := respond("UserPromptSubmit", "block"); out["continue"] != false {
		t.Fatalf("prompt block rendered %v", out)
	}
}
