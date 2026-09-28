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

//go:build !windows

package image

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func newMockServer(t *testing.T) (*mockLLM, *httptest.Server) {
	t.Helper()
	m := newMockLLM(builtinMockScenarios...)
	srv := httptest.NewServer(m)
	t.Cleanup(srv.Close)
	return m, srv
}

func mockPost(t *testing.T, url, body string, headers map[string]string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

// sseEvents parses an event stream into (event, data) pairs.
func sseEvents(t *testing.T, body string) [][2]string {
	t.Helper()
	var out [][2]string
	var name string
	sc := bufio.NewScanner(strings.NewReader(body))
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "event: "):
			name = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			data := strings.TrimPrefix(line, "data: ")
			if data != "[DONE]" && !json.Valid([]byte(data)) {
				t.Fatalf("event %s carries invalid JSON: %s", name, data)
			}
			out = append(out, [2]string{name, data})
		}
	}
	return out
}

// jsonHas reports whether some object in doc holds key: want, looking into
// string values that are JSON documents themselves (tool-call arguments).
func jsonHas(doc interface{}, key string, want interface{}) bool {
	switch v := doc.(type) {
	case map[string]interface{}:
		for k, child := range v {
			if (k == key && reflect.DeepEqual(child, want)) || jsonHas(child, key, want) {
				return true
			}
		}
	case []interface{}:
		for _, child := range v {
			if jsonHas(child, key, want) {
				return true
			}
		}
	case string:
		var inner interface{}
		if strings.HasPrefix(v, "{") && json.Unmarshal([]byte(v), &inner) == nil {
			return jsonHas(inner, key, want)
		}
	}
	return false
}

func quoteJSON(s string) string {
	raw, _ := json.Marshal(s)
	return string(raw)
}

const (
	anthropicTools        = `"tools":[{"name":"Bash","input_schema":{}},{"name":"Read","input_schema":{}}]`
	hermesTerminalTool    = `{"type":"function","function":{"name":"terminal","parameters":{"type":"object","properties":{"command":{"type":"string"},"background":{"type":"boolean"}},"required":["command"]}}}`
	openHandsTerminal     = `{"type":"function","function":{"name":"terminal","parameters":{"type":"object","properties":{"command":{"type":"string"},"is_input":{"type":"boolean"},"security_risk":{"type":"string","enum":["UNKNOWN","LOW","MEDIUM","HIGH"]}},"required":["command","security_risk"]}}}`
	antigravityRunCommand = `{"functionDeclarations":[{"name":"view_file","parameters":{"type":"object"}},{"name":"run_command","parametersJsonSchema":{"type":"object","properties":{"CommandLine":{"type":"string"},"Cwd":{"type":"string"},"WaitMsBeforeAsync":{"type":"integer"}},"required":["CommandLine","Cwd","WaitMsBeforeAsync"]}}]}`
)

// TestMockLLMToolLoops drives every wire protocol the built-in mock speaks
// the way its harnesses do: a scenario prompt gets one shell tool call in
// the shape the advertised tool takes, the tool's result closes the scenario
// with text, and a request without a shell tool (titles, summaries, quota
// probes) or with an unscripted prompt is answered with text and burns no
// scripted turn.
func TestMockLLMToolLoops(t *testing.T) {
	m, srv := newMockServer(t)
	blockCmd, allowCmd := "echo BLOCKME > "+builtinBlockSideEffect, "echo dc-hookfire-allowed > "+builtinAllowSideEffect
	block, allow := quoteJSON(builtinBlockPrompt), quoteJSON(builtinAllowPrompt)
	messages := `{"role":"user","content":[{"type":"text","text":"<system-reminder>ctx</system-reminder>"},{"type":"text","text":` + block + `}]}`
	responses := `{"type":"message","role":"user","content":[{"type":"input_text","text":"<environment_context>cwd</environment_context>"}]},` +
		`{"type":"message","role":"user","content":[{"type":"input_text","text":` + allow + `}]}`
	chat := func(tool string) string {
		return `{"model":"mock-model","messages":[{"role":"system","content":"sys"},{"role":"user","content":` + block + `}],"tools":[` + tool + `]}`
	}
	for _, tc := range []struct {
		name, path, body string
		want             []interface{} // key, value pairs the answer holds
		says, lacks      string        // text the answer does and does not contain
	}{
		// Anthropic Messages: Claude Code's Bash, OpenCode's and the Copilot
		// CLI's bash (Bash wins when both are advertised).
		{"messages", "/v1/messages?beta=true", `{"model":"claude-x","max_tokens":1024,"messages":[` + messages + `],` + anthropicTools + `}`,
			[]interface{}{"stop_reason", "tool_use", "model", "claude-x", "name", "Bash", "command", blockCmd}, "", ""},
		{"messages lowercase bash", "/v1/messages", `{"model":"m","messages":[{"role":"user","content":` + allow + `}],"tools":[{"name":"read"},{"name":"bash"},{"name":"edit"}]}`,
			[]interface{}{"stop_reason", "tool_use", "name", "bash", "description", "DefenseClaw hook-fire probe", "command", allowCmd}, "", ""},
		{"messages mixed bash", "/v1/messages", `{"model":"m","messages":[{"role":"user","content":` + block + `}],"tools":[{"name":"bash"},{"name":"Bash"}]}`,
			[]interface{}{"name", "Bash"}, "", ""},
		{"messages follow-up", "/v1/messages", `{"model":"claude-x","messages":[` + messages + `,{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"Bash","input":{}}]},` +
			`{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"blocked"}]}],` + anthropicTools + `}`,
			[]interface{}{"stop_reason", "end_turn"}, "blocked by policy", "tool_use"},
		{"messages without tools", "/v1/messages?beta=true", `{"model":"claude-x","max_tokens":1,"messages":[` + messages + `]}`, nil, mockAuxText, "tool_use"},
		{"messages unscripted", "/v1/messages", `{"messages":[{"role":"user","content":"hello"}],` + anthropicTools + `}`, nil, mockAuxText, "tool_use"},

		// OpenAI Responses (Codex's shell tools).
		{"responses shell_command", "/v1/responses", `{"model":"mock-model","input":[` + responses + `],"tools":[{"type":"function","name":"shell_command"}]}`,
			[]interface{}{"status", "completed", "name", "shell_command", "command", allowCmd}, "", ""},
		{"responses exec_command", "/v1/responses", `{"input":[` + responses + `],"tools":[{"type":"function","name":"exec_command"}]}`,
			[]interface{}{"name", "exec_command", "cmd", allowCmd}, "", ""},
		{"responses shell", "/v1/responses", `{"input":[` + responses + `],"tools":[{"type":"function","name":"shell"}]}`,
			[]interface{}{"name", "shell", "command", []interface{}{"bash", "-lc", allowCmd}}, "", ""},
		{"responses local_shell", "/v1/responses", `{"input":[` + responses + `],"tools":[{"type":"local_shell"}]}`,
			[]interface{}{"type", "local_shell_call"}, "", ""},
		{"responses follow-up", "/responses", `{"input":[` + responses + `,{"type":"function_call","name":"shell_command","call_id":"c1","arguments":"{}"},` +
			`{"type":"function_call_output","call_id":"c1","output":"ok"}],"tools":[{"type":"function","name":"shell_command"}]}`,
			nil, "marker file was written", `function_call"`},
		{"responses without a shell tool", "/v1/responses", `{"input":[` + responses + `],"tools":[{"type":"function","name":"apply_patch"}]}`,
			nil, "no shell tool among apply_patch", "function_call"},

		// Chat Completions (Hermes and OpenHands terminal tools).
		{"chat hermes", "/v1/chat/completions", chat(hermesTerminalTool),
			[]interface{}{"finish_reason", "tool_calls", "name", "terminal", "command", blockCmd}, "", ""},
		{"chat openhands", "/v1/chat/completions", chat(openHandsTerminal),
			[]interface{}{"finish_reason", "tool_calls", "name", "terminal", "command", blockCmd, "security_risk", "UNKNOWN"}, "", ""},
		{"chat follow-up", "/chat/completions", `{"model":"mock-model","messages":[{"role":"user","content":[{"type":"text","text":` + block + `}]},` +
			`{"role":"assistant","content":null,"tool_calls":[{"id":"c1","type":"function","function":{"name":"terminal","arguments":"{}"}}]},` +
			`{"role":"tool","tool_call_id":"c1","content":"blocked"}],"tools":[` + openHandsTerminal + `]}`, nil, "blocked by policy", "tool_calls\":["},
		{"chat without tools", "/v1/chat/completions", `{"messages":[{"role":"user","content":` + allow + `}]}`, nil, "no shell tool", "tool_calls\":["},

		// Gemini (Antigravity's run_command).
		{"gemini", "/v1beta/models/gemini-3.1-pro-preview:streamGenerateContent?alt=sse", `{"contents":[{"role":"user","parts":[{"text":` + block + `}]}],"tools":[` + antigravityRunCommand + `]}`,
			[]interface{}{"name", "run_command", "CommandLine", blockCmd, "WaitMsBeforeAsync", float64(30), "Cwd", "/tmp"}, "", ""},
		{"gemini follow-up", "/v1beta/models/m:generateContent", `{"contents":[{"role":"user","parts":[{"text":` + block + `}]},` +
			`{"role":"model","parts":[{"functionCall":{"name":"run_command","args":{}}}]},` +
			`{"role":"user","parts":[{"functionResponse":{"name":"run_command","response":{"output":"denied"}}}]}],"tools":[` + antigravityRunCommand + `]}`,
			nil, "blocked by policy", "functionCall"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, body := mockPost(t, srv.URL+tc.path, tc.body, nil)
			if code != http.StatusOK || !strings.Contains(body, tc.says) || (tc.lacks != "" && strings.Contains(body, tc.lacks)) {
				t.Fatalf("status %d, want one saying %q without %q: %s", code, tc.says, tc.lacks, body)
			}
			var doc interface{}
			if err := json.Unmarshal([]byte(strings.TrimPrefix(strings.TrimSpace(body), "data: ")), &doc); err != nil {
				t.Fatalf("answer is not JSON: %v\n%s", err, body)
			}
			for i := 0; i+1 < len(tc.want); i += 2 {
				if !jsonHas(doc, tc.want[i].(string), tc.want[i+1]) {
					t.Fatalf("answer lacks %v = %#v: %s", tc.want[i], tc.want[i+1], body)
				}
			}
		})
	}
	want := map[string]int{builtinBlockMarker: 5, "write the marker file": 5}
	if served := m.toolCallsServed(); !reflect.DeepEqual(served, want) {
		t.Fatalf("tool calls served = %v, want %v", served, want)
	}
}

// TestMockLLMStreams checks the streamed shapes: Anthropic's event order and
// input_json_delta pieces, the Responses events with their sequence numbers,
// and the Chat Completions chunks, each carrying the scenario's tool call.
func TestMockLLMStreams(t *testing.T) {
	_, srv := newMockServer(t)
	allowCmd := "echo dc-hookfire-allowed > " + builtinAllowSideEffect
	stream := func(path, body string) [][2]string {
		t.Helper()
		code, out := mockPost(t, srv.URL+path, body, nil)
		if code != http.StatusOK {
			t.Fatalf("%s: status %d", path, code)
		}
		return sseEvents(t, out)
	}
	names := func(events [][2]string) string {
		var out []string
		for _, ev := range events {
			out = append(out, ev[0])
		}
		return strings.Join(out, ",")
	}

	events := stream("/v1/messages", `{"model":"claude-x","stream":true,"messages":[{"role":"user","content":`+quoteJSON(builtinAllowPrompt)+`}],`+anthropicTools+`}`)
	var partial strings.Builder
	for _, ev := range events {
		var data struct {
			Delta struct {
				Type        string `json:"type"`
				PartialJSON string `json:"partial_json"`
				StopReason  string `json:"stop_reason"`
			} `json:"delta"`
		}
		_ = json.Unmarshal([]byte(ev[1]), &data)
		if data.Delta.Type == "input_json_delta" {
			partial.WriteString(data.Delta.PartialJSON)
		}
		if ev[0] == "message_delta" && data.Delta.StopReason != "tool_use" {
			t.Fatalf("message_delta = %s, want the tool_use stop reason", ev[1])
		}
	}
	if got := names(events); !strings.HasPrefix(got, "message_start,ping,content_block_start,content_block_delta") ||
		!strings.HasSuffix(got, "content_block_stop,message_delta,message_stop") {
		t.Fatalf("anthropic event order = %s", got)
	}
	var input map[string]string
	if err := json.Unmarshal([]byte(partial.String()), &input); err != nil || input["command"] != allowCmd {
		t.Fatalf("streamed tool input = %q (%v)", partial.String(), err)
	}

	events = stream("/v1/responses", `{"model":"mock-model","stream":true,"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":`+
		quoteJSON(builtinBlockPrompt)+`}]}],"tools":[{"type":"function","name":"shell_command"}]}`)
	for i, ev := range events {
		var data struct {
			Type string `json:"type"`
			Seq  int    `json:"sequence_number"`
		}
		if err := json.Unmarshal([]byte(ev[1]), &data); err != nil || data.Type != ev[0] || data.Seq != i {
			t.Fatalf("responses event %d = %s %s", i, ev[0], ev[1])
		}
	}
	if got := names(events); got != "response.created,response.output_item.added,response.output_item.done,response.completed" || !strings.Contains(events[3][1], "echo BLOCKME") {
		t.Fatalf("responses events = %s, completed %s", got, events[len(events)-1][1])
	}
	// A text answer streams deltas.
	if got := names(stream("/v1/responses", `{"stream":true,"input":"hello"}`)); !strings.Contains(got, "response.output_text.delta") {
		t.Fatalf("text stream = %s", got)
	}

	events = stream("/v1/chat/completions", `{"stream":true,"messages":[{"role":"user","content":`+quoteJSON(builtinAllowPrompt)+`}],"tools":[`+hermesTerminalTool+`]}`)
	var name, arguments, finish string
	for _, ev := range events {
		if ev[1] == "[DONE]" {
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
		if err := json.Unmarshal([]byte(ev[1]), &chunk); err != nil || chunk.Object != "chat.completion.chunk" {
			t.Fatalf("chunk %s: %v", ev[1], err)
		}
		for _, call := range chunk.Choices[0].Delta.ToolCalls {
			name += call.Function.Name
			arguments += call.Function.Arguments
		}
		if chunk.Choices[0].FinishReason != nil {
			finish = *chunk.Choices[0].FinishReason
		}
	}
	var args map[string]string
	if err := json.Unmarshal([]byte(arguments), &args); err != nil || name != "terminal" || finish != "tool_calls" ||
		args["command"] != allowCmd || events[len(events)-1][1] != "[DONE]" {
		t.Fatalf("streamed call %q %q finish %q: %v", name, arguments, finish, err)
	}
}

func TestMockLLMAuxiliaryRoutes(t *testing.T) {
	_, srv := newMockServer(t)
	for _, tc := range []struct {
		method, path string
		headers      map[string]string
		body         string
		code         int
		says         []string
	}{
		{http.MethodGet, "/v1/models", map[string]string{"anthropic-version": "2023-06-01"}, "", 200, []string{`"type":"model"`, `"has_more":false`}},
		{http.MethodGet, "/v1/models/claude-x", map[string]string{"x-api-key": "k"}, "", 200, []string{`"id":"claude-x"`}},
		{http.MethodGet, "/models", nil, "", 200, []string{`"object":"list"`, `"mock-model"`}},
		{http.MethodGet, "/v1/responses", map[string]string{"Upgrade": "websocket", "Connection": "Upgrade"}, "", http.StatusUpgradeRequired, nil},
		{http.MethodPost, "/v1/messages/count_tokens", nil, `{"messages":[{"role":"user","content":"abcdefgh"}]}`, 200, []string{`"input_tokens"`}},
		{http.MethodPost, "/v1/messages", nil, `{not json`, http.StatusBadRequest, nil},
		{http.MethodPost, "/v1/embeddings", nil, `{}`, http.StatusNotFound, nil},
		{http.MethodHead, "/", nil, "", 200, nil},
	} {
		req, _ := http.NewRequest(tc.method, srv.URL+tc.path, strings.NewReader(tc.body))
		for k, v := range tc.headers {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != tc.code {
			t.Fatalf("%s %s = %d %s", tc.method, tc.path, resp.StatusCode, raw)
		}
		for _, want := range tc.says {
			if !strings.Contains(string(raw), want) {
				t.Fatalf("%s %s = %s, want %s", tc.method, tc.path, raw, want)
			}
		}
	}
}
