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

package image

import (
	"encoding/json"
	"strings"
	"testing"
)

// The shell tool schemas the mock must fill, as the harnesses advertise them.
const (
	hermesTerminalTool    = `{"type":"function","function":{"name":"terminal","parameters":{"type":"object","properties":{"command":{"type":"string"},"background":{"type":"boolean"}},"required":["command"]}}}`
	openHandsTerminal     = `{"type":"function","function":{"name":"terminal","parameters":{"type":"object","properties":{"command":{"type":"string"},"is_input":{"type":"boolean"},"security_risk":{"type":"string","enum":["UNKNOWN","LOW","MEDIUM","HIGH"]}},"required":["command","security_risk"]}}}`
	antigravityRunCommand = `{"functionDeclarations":[{"name":"view_file","parameters":{"type":"object"}},{"name":"run_command","parametersJsonSchema":{"type":"object","properties":{"CommandLine":{"type":"string"},"Cwd":{"type":"string"},"WaitMsBeforeAsync":{"type":"integer"}},"required":["CommandLine","Cwd","WaitMsBeforeAsync"]}}]}`
)

func chatToolCall(t *testing.T, body string) (string, map[string]interface{}) {
	t.Helper()
	var resp struct {
		Choices []struct {
			Message struct {
				Content   *string `json:"content"`
				ToolCalls []struct {
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil || len(resp.Choices) != 1 {
		t.Fatalf("chat completion %s: %v", body, err)
	}
	msg := resp.Choices[0].Message
	if len(msg.ToolCalls) == 0 {
		return "", nil
	}
	var args map[string]interface{}
	if err := json.Unmarshal([]byte(msg.ToolCalls[0].Function.Arguments), &args); err != nil {
		t.Fatalf("tool arguments %q: %v", msg.ToolCalls[0].Function.Arguments, err)
	}
	if resp.Choices[0].FinishReason != "tool_calls" {
		t.Fatalf("finish_reason = %q", resp.Choices[0].FinishReason)
	}
	return msg.ToolCalls[0].Function.Name, args
}

func TestMockLLMChatCompletionsToolLoop(t *testing.T) {
	m, srv := newMockServer(t)
	for _, tc := range []struct {
		name, tool string
		wantArgs   map[string]interface{}
	}{
		{"hermes", hermesTerminalTool, map[string]interface{}{"command": "echo BLOCKME > " + builtinBlockSideEffect}},
		{"openhands", openHandsTerminal, map[string]interface{}{"command": "echo BLOCKME > " + builtinBlockSideEffect, "security_risk": "UNKNOWN"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first := `{"model":"mock-model","messages":[{"role":"system","content":"sys"},{"role":"user","content":"` + builtinBlockPrompt + `"}],"tools":[` + tc.tool + `]}`
			code, body := mockPost(t, srv.URL+"/v1/chat/completions", first, nil)
			if code != 200 {
				t.Fatalf("status %d: %s", code, body)
			}
			name, args := chatToolCall(t, body)
			if name != "terminal" {
				t.Fatalf("tool = %q in %s", name, body)
			}
			for k, v := range tc.wantArgs {
				if args[k] != v {
					t.Fatalf("args[%s] = %#v, want %#v", k, args[k], v)
				}
			}
			second := `{"model":"mock-model","messages":[{"role":"user","content":[{"type":"text","text":"` + builtinBlockPrompt + `"}]},` +
				`{"role":"assistant","content":null,"tool_calls":[{"id":"c1","type":"function","function":{"name":"terminal","arguments":"{}"}}]},` +
				`{"role":"tool","tool_call_id":"c1","content":"blocked"}],"tools":[` + tc.tool + `]}`
			_, body = mockPost(t, srv.URL+"/chat/completions", second, nil)
			if name, _ := chatToolCall(t, body); name != "" || !strings.Contains(body, "blocked by policy") {
				t.Fatalf("second turn = %s", body)
			}
		})
	}
	if got := m.toolCallsServed()[builtinBlockMarker]; got != 2 {
		t.Fatalf("tool calls served = %d, want 2", got)
	}
	// A request without a shell tool (titles, summaries) burns no turn.
	_, body := mockPost(t, srv.URL+"/v1/chat/completions", `{"messages":[{"role":"user","content":"`+builtinAllowPrompt+`"}]}`, nil)
	if !strings.Contains(body, "no shell tool") {
		t.Fatalf("toolless request = %s", body)
	}
}

func TestMockLLMChatCompletionsStream(t *testing.T) {
	_, srv := newMockServer(t)
	req := `{"stream":true,"messages":[{"role":"user","content":"` + builtinAllowPrompt + `"}],"tools":[` + hermesTerminalTool + `]}`
	code, body := mockPost(t, srv.URL+"/v1/chat/completions", req, nil)
	if code != 200 || !strings.HasSuffix(strings.TrimSpace(body), "data: [DONE]") {
		t.Fatalf("status %d body %s", code, body)
	}
	var name, arguments, finish string
	for _, line := range strings.Split(body, "\n") {
		data, ok := strings.CutPrefix(line, "data: ")
		if !ok || data == "[DONE]" {
			continue
		}
		var chunk struct {
			Object  string `json:"object"`
			Choices []struct {
				Delta struct {
					ToolCalls []struct {
						Function struct {
							Name      string `json:"name"`
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"delta"`
				FinishReason *string `json:"finish_reason"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(data), &chunk); err != nil || chunk.Object != "chat.completion.chunk" {
			t.Fatalf("chunk %s: %v", data, err)
		}
		for _, tc := range chunk.Choices[0].Delta.ToolCalls {
			name += tc.Function.Name
			arguments += tc.Function.Arguments
		}
		if chunk.Choices[0].FinishReason != nil {
			finish = *chunk.Choices[0].FinishReason
		}
	}
	var args map[string]string
	if err := json.Unmarshal([]byte(arguments), &args); err != nil || name != "terminal" || finish != "tool_calls" ||
		args["command"] != "echo dc-hookfire-allowed > "+builtinAllowSideEffect {
		t.Fatalf("streamed call %q %q finish %q: %v", name, arguments, finish, err)
	}
}

func TestMockLLMGeminiToolLoop(t *testing.T) {
	_, srv := newMockServer(t)
	url := srv.URL + "/v1beta/models/gemini-3.1-pro-preview:streamGenerateContent?alt=sse"
	first := `{"contents":[{"role":"user","parts":[{"text":"` + builtinBlockPrompt + `"}]}],"tools":[` + antigravityRunCommand + `]}`
	code, body := mockPost(t, url, first, nil)
	data, ok := strings.CutPrefix(strings.TrimSpace(body), "data: ")
	if code != 200 || !ok {
		t.Fatalf("status %d body %s", code, body)
	}
	var resp struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text         string `json:"text"`
					FunctionCall struct {
						Name string                 `json:"name"`
						Args map[string]interface{} `json:"args"`
					} `json:"functionCall"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal([]byte(data), &resp); err != nil {
		t.Fatal(err)
	}
	call := resp.Candidates[0].Content.Parts[0].FunctionCall
	if call.Name != "run_command" || call.Args["CommandLine"] != "echo BLOCKME > "+builtinBlockSideEffect ||
		call.Args["WaitMsBeforeAsync"] != float64(30) || call.Args["Cwd"] != "/tmp" {
		t.Fatalf("function call = %#v", call)
	}
	second := `{"contents":[{"role":"user","parts":[{"text":"` + builtinBlockPrompt + `"}]},` +
		`{"role":"model","parts":[{"functionCall":{"name":"run_command","args":{}}}]},` +
		`{"role":"user","parts":[{"functionResponse":{"name":"run_command","response":{"output":"denied"}}}]}],"tools":[` + antigravityRunCommand + `]}`
	_, body = mockPost(t, srv.URL+"/v1beta/models/m:generateContent", second, nil)
	if !strings.Contains(body, "blocked by policy") || strings.Contains(body, "functionCall") {
		t.Fatalf("second turn = %s", body)
	}
}

func TestHookSinkAdapters(t *testing.T) {
	for _, tc := range []struct {
		name, event, body string
		want              bool
	}{
		{"hermes", "pre_tool_call", `{"tool_input":{"command":"echo BLOCKME"}}`, true},
		{"hermes", "PreToolUse", `{"tool_input":{"command":"echo BLOCKME"}}`, false},
		{"openhands", "PreToolUse", `{"tool_input":{"command":"echo BLOCKME"}}`, true},
		{"openhands", "PreToolUse", `{"message":"BLOCKME"}`, false},
		{"antigravity", "PreToolUse", `{"toolInput":{"CommandLine":"echo BLOCKME"}}`, true},
		{"antigravity", "PostToolUse", `{"toolInput":{"CommandLine":"echo BLOCKME"}}`, false},
		{"claudecode", "PreToolUse", `{"tool_input":{"command":"echo BLOCKME"}}`, true},
	} {
		var payload map[string]json.RawMessage
		_ = json.Unmarshal([]byte(tc.body), &payload)
		if got := hookSinkAdapters[tc.name].blocks(tc.event, []byte(tc.body), payload, builtinBlockMarker); got != tc.want {
			t.Errorf("%s %s %s: blocks = %t, want %t", tc.name, tc.event, tc.body, got, tc.want)
		}
	}
	// The hook-only harnesses the Chat Completions, Gemini and Responses
	// mocks drive (OmniGent's policy answers in its own shape).
	for _, name := range []string{"antigravity", "hermes", "omnigent", "openhands"} {
		adapter := hookSinkAdapters[name]
		if adapter.hookOutput == nil && name != "omnigent" {
			t.Errorf("%s adapter renders no hook_output", name)
		}
		if _, ok := requiredHookEvents[name]; !ok {
			t.Errorf("%s adapter has no required hook events", name)
		}
		if _, ok := builtinMockLaunch[name]; !ok {
			t.Errorf("%s adapter has no built-in mock wiring", name)
		}
	}
}
