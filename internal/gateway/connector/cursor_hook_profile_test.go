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

func TestCursorProfileDecodeDocumentedSpecializedPayloads(t *testing.T) {
	tests := []struct {
		name        string
		payload     map[string]interface{}
		wantTool    string
		wantContent string
		wantDir     string
		wantArgs    map[string]interface{}
	}{
		{
			name: "shell pre-execution becomes an authoritative shell call",
			payload: map[string]interface{}{
				"hook_event_name": "beforeShellExecution",
				"command":         "az account show",
				"cwd":             `C:\work`,
				"sandbox":         false,
			},
			wantTool: "Shell",
			wantArgs: map[string]interface{}{
				"command": "az account show",
				"cwd":     `C:\work`,
			},
		},
		{
			name: "Windows shell pre-execution omits blank optional cwd",
			payload: map[string]interface{}{
				"hook_event_name": "beforeShellExecution",
				"command":         "az keyvault secret show --vault-name missing --name test",
				"cwd":             "",
				"sandbox":         false,
			},
			wantTool: "Shell",
			wantArgs: map[string]interface{}{
				"command": "az keyvault secret show --vault-name missing --name test",
			},
		},
		{
			name: "MCP params JSON string becomes a typed argument object",
			payload: map[string]interface{}{
				"hook_event_name": "beforeMCPExecution",
				"tool_name":       "search",
				"tool_input":      `{"query":"status"}`,
				"mcp_server_name": "local-docs",
			},
			wantTool: "search",
			wantArgs: map[string]interface{}{"query": "status"},
		},
		{
			name: "file read exposes both canonical path and content",
			payload: map[string]interface{}{
				"hook_event_name": "beforeReadFile",
				"file_path":       `C:\work\notes.txt`,
				"content":         "reviewed content",
			},
			wantTool: "Read",
			wantArgs: map[string]interface{}{
				"path":      `C:\work\notes.txt`,
				"file_path": `C:\work\notes.txt`,
				"content":   "reviewed content",
			},
		},
		{
			name: "shell output reaches result scanning",
			payload: map[string]interface{}{
				"hook_event_name": "afterShellExecution",
				"command":         "Write-Output ok",
				"output":          "ok",
			},
			wantTool:    "Shell",
			wantContent: "ok",
			wantDir:     "tool_result",
			wantArgs:    map[string]interface{}{"command": "Write-Output ok"},
		},
		{
			name: "MCP result reaches result scanning",
			payload: map[string]interface{}{
				"hook_event_name": "afterMCPExecution",
				"tool_name":       "search",
				"tool_input":      `{"query":"status"}`,
				"result_json":     `{"items":[]}`,
			},
			wantTool:    "search",
			wantContent: `{"items":[]}`,
			wantDir:     "tool_result",
			wantArgs:    map[string]interface{}{"query": "status"},
		},
		{
			name: "subagent task reaches prompt scanning",
			payload: map[string]interface{}{
				"hook_event_name": "subagentStart",
				"task":            "Review the authentication flow",
			},
			wantTool:    "Task",
			wantContent: "Review the authentication flow",
			wantDir:     "prompt",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := cursorProfileDecode(test.payload)
			if req.ToolName != test.wantTool {
				t.Fatalf("ToolName=%q want %q", req.ToolName, test.wantTool)
			}
			if req.Content != test.wantContent {
				t.Fatalf("Content=%q want %q", req.Content, test.wantContent)
			}
			if req.Direction != test.wantDir {
				t.Fatalf("Direction=%q want %q", req.Direction, test.wantDir)
			}
			if test.wantArgs == nil {
				if req.ToolArgsAuthoritative {
					t.Fatal("non-tool payload unexpectedly claimed authoritative args")
				}
				return
			}
			if !req.ToolArgsAuthoritative {
				t.Fatal("specialized tool payload did not claim authoritative args")
			}
			var got map[string]interface{}
			if err := json.Unmarshal(req.ToolArgs, &got); err != nil {
				t.Fatalf("ToolArgs are not an object: %v (%s)", err, req.ToolArgs)
			}
			wantJSON, _ := json.Marshal(test.wantArgs)
			gotJSON, _ := json.Marshal(got)
			if string(gotJSON) != string(wantJSON) {
				t.Fatalf("ToolArgs=%s want %s", gotJSON, wantJSON)
			}
		})
	}
}

func TestCursorProfileDecodePreservesMalformedMCPInputForScanning(t *testing.T) {
	req := cursorProfileDecode(map[string]interface{}{
		"hook_event_name": "beforeMCPExecution",
		"tool_name":       "search",
		"tool_input":      "not-json but still inspectable",
	})
	var args map[string]interface{}
	if err := json.Unmarshal(req.ToolArgs, &args); err != nil {
		t.Fatal(err)
	}
	if args["raw_input"] != "not-json but still inspectable" {
		t.Fatalf("malformed input was dropped: %#v", args)
	}
}

func TestCursorCurrentEnforcementEventsMatchDocumentedWireSemantics(t *testing.T) {
	profile := NewCursorConnector().HookProfile(SetupOpts{})
	if got := profile.MapVerdict(HookVerdictInput{
		RawAction: "block", Event: "subagentStart", Mode: "action", Caps: profile.Capabilities,
	}); got.Action != "block" || got.WouldBlock {
		t.Fatalf("subagentStart block mapping=%+v, want enforced block", got)
	}
	if got := profile.MapVerdict(HookVerdictInput{
		RawAction: "block", Event: "stop", Mode: "action", Caps: profile.Capabilities,
	}); got.Action != "allow" || !got.WouldBlock {
		t.Fatalf("stop block mapping=%+v, want follow-up-only allow/would-block", got)
	}
}
