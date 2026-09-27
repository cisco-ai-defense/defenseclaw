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
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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
			if !json.Valid([]byte(data)) {
				t.Fatalf("event %s carries invalid JSON: %s", name, data)
			}
			out = append(out, [2]string{name, data})
		}
	}
	return out
}

const anthropicTools = `"tools":[{"name":"Bash","input_schema":{}},{"name":"Read","input_schema":{}}]`

func TestMockLLMAnthropicToolLoop(t *testing.T) {
	m, srv := newMockServer(t)
	url := srv.URL + "/v1/messages?beta=true"
	prompt := `{"role":"user","content":[{"type":"text","text":"<system-reminder>ctx</system-reminder>"},{"type":"text","text":"` + builtinBlockPrompt + `"}]}`

	// First turn: one Bash tool call carrying the scenario command.
	code, body := mockPost(t, url, `{"model":"claude-x","max_tokens":1024,"messages":[`+prompt+`],`+anthropicTools+`}`, nil)
	if code != 200 {
		t.Fatalf("status %d: %s", code, body)
	}
	var msg struct {
		Content []struct {
			Type  string            `json:"type"`
			ID    string            `json:"id"`
			Name  string            `json:"name"`
			Input map[string]string `json:"input"`
		} `json:"content"`
		StopReason string `json:"stop_reason"`
		Model      string `json:"model"`
	}
	if err := json.Unmarshal([]byte(body), &msg); err != nil {
		t.Fatal(err)
	}
	if msg.StopReason != "tool_use" || len(msg.Content) != 1 || msg.Content[0].Name != "Bash" || msg.Model != "claude-x" ||
		msg.Content[0].Input["command"] != "echo BLOCKME > "+builtinBlockSideEffect {
		t.Fatalf("first turn = %s", body)
	}

	// After the tool result the scenario closes with text.
	followUp := prompt + `,{"role":"assistant","content":[{"type":"tool_use","id":"` + msg.Content[0].ID + `","name":"Bash","input":{}}]},` +
		`{"role":"user","content":[{"type":"tool_result","tool_use_id":"` + msg.Content[0].ID + `","content":"blocked"}]}`
	_, body = mockPost(t, url, `{"model":"claude-x","messages":[`+followUp+`],`+anthropicTools+`}`, nil)
	if !strings.Contains(body, `"stop_reason":"end_turn"`) || !strings.Contains(body, "blocked by policy") {
		t.Fatalf("second turn = %s", body)
	}

	// A request without the Bash tool (title generation, quota probe) is
	// answered with text and burns no scripted turn.
	_, body = mockPost(t, url, `{"model":"claude-x","max_tokens":1,"messages":[`+prompt+`]}`, nil)
	if !strings.Contains(body, mockAuxText) || strings.Contains(body, "tool_use") {
		t.Fatalf("aux request = %s", body)
	}
	// An unscripted prompt gets text as well.
	_, body = mockPost(t, url, `{"messages":[{"role":"user","content":"hello"}],`+anthropicTools+`}`, nil)
	if !strings.Contains(body, mockAuxText) {
		t.Fatalf("unscripted prompt = %s", body)
	}
	if served := m.toolCallsServed(); served[builtinBlockMarker] != 1 || len(served) != 1 {
		t.Fatalf("tool calls served = %v", served)
	}
}

func TestMockLLMAnthropicStreams(t *testing.T) {
	_, srv := newMockServer(t)
	body := `{"model":"claude-x","stream":true,"messages":[{"role":"user","content":"` + builtinAllowPrompt + `"}],` + anthropicTools + `}`
	code, out := mockPost(t, srv.URL+"/v1/messages", body, nil)
	if code != 200 {
		t.Fatalf("status %d", code)
	}
	events := sseEvents(t, out)
	var names []string
	var partial strings.Builder
	for _, ev := range events {
		names = append(names, ev[0])
		var data struct {
			Delta struct {
				Type        string `json:"type"`
				PartialJSON string `json:"partial_json"`
			} `json:"delta"`
		}
		_ = json.Unmarshal([]byte(ev[1]), &data)
		if data.Delta.Type == "input_json_delta" {
			partial.WriteString(data.Delta.PartialJSON)
		}
	}
	joined := strings.Join(names, ",")
	if !strings.HasPrefix(joined, "message_start,ping,content_block_start,content_block_delta") ||
		!strings.HasSuffix(joined, "content_block_stop,message_delta,message_stop") {
		t.Fatalf("event order = %s", joined)
	}
	var input map[string]string
	if err := json.Unmarshal([]byte(partial.String()), &input); err != nil || input["command"] != "echo dc-hookfire-allowed > "+builtinAllowSideEffect {
		t.Fatalf("streamed tool input = %q (%v)", partial.String(), err)
	}
	if !strings.Contains(out, `"stop_reason":"tool_use"`) {
		t.Fatal("message_delta must carry the tool_use stop reason")
	}
}

func TestMockLLMResponsesToolLoop(t *testing.T) {
	_, srv := newMockServer(t)
	userItem := `{"type":"message","role":"user","content":[{"type":"input_text","text":"` + builtinAllowPrompt + `"}]}`
	env := `{"type":"message","role":"user","content":[{"type":"input_text","text":"<environment_context>cwd</environment_context>"}]}`
	for _, tc := range []struct {
		tools    string
		wantName string
		wantArg  string
	}{
		{`[{"type":"function","name":"shell_command"}]`, "shell_command", `"command":"echo dc-hookfire-allowed`},
		{`[{"type":"function","name":"exec_command"}]`, "exec_command", `"cmd":"echo dc-hookfire-allowed`},
		{`[{"type":"function","name":"shell"}]`, "shell", `"command":["bash","-lc","echo dc-hookfire-allowed`},
		{`[{"type":"local_shell"}]`, "", `"type":"local_shell_call"`},
	} {
		code, body := mockPost(t, srv.URL+"/v1/responses", `{"model":"mock-model","input":[`+env+`,`+userItem+`],"tools":`+tc.tools+`}`, nil)
		if code != 200 {
			t.Fatalf("status %d: %s", code, body)
		}
		var resp struct {
			Status string                   `json:"status"`
			Output []map[string]interface{} `json:"output"`
		}
		if err := json.Unmarshal([]byte(body), &resp); err != nil || resp.Status != "completed" || len(resp.Output) != 1 {
			t.Fatalf("%s: response = %s", tc.tools, body)
		}
		item, _ := json.Marshal(resp.Output[0])
		if (tc.wantName != "" && resp.Output[0]["name"] != tc.wantName) || !strings.Contains(strings.ReplaceAll(string(item), `\"`, `"`), tc.wantArg) {
			t.Fatalf("%s: item = %s", tc.tools, item)
		}
	}
	// The call's output closes the scenario.
	followUp := userItem + `,{"type":"function_call","name":"shell_command","call_id":"c1","arguments":"{}"},{"type":"function_call_output","call_id":"c1","output":"ok"}`
	_, body := mockPost(t, srv.URL+"/responses", `{"input":[`+followUp+`],"tools":[{"type":"function","name":"shell_command"}]}`, nil)
	if !strings.Contains(body, "marker file was written") || strings.Contains(body, "function_call\"") {
		t.Fatalf("follow-up = %s", body)
	}
	// No shell tool: the mock says so instead of inventing one.
	_, body = mockPost(t, srv.URL+"/v1/responses", `{"input":[`+userItem+`],"tools":[{"type":"function","name":"apply_patch"}]}`, nil)
	if !strings.Contains(body, "no shell tool among apply_patch") {
		t.Fatalf("no-shell = %s", body)
	}
}

func TestMockLLMResponsesStreams(t *testing.T) {
	_, srv := newMockServer(t)
	body := `{"model":"mock-model","stream":true,"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"` + builtinBlockPrompt + `"}]}],"tools":[{"type":"function","name":"shell_command"}]}`
	_, out := mockPost(t, srv.URL+"/v1/responses", body, nil)
	events := sseEvents(t, out)
	var names []string
	for i, ev := range events {
		names = append(names, ev[0])
		var data struct {
			Type string `json:"type"`
			Seq  int    `json:"sequence_number"`
		}
		if err := json.Unmarshal([]byte(ev[1]), &data); err != nil || data.Type != ev[0] || data.Seq != i {
			t.Fatalf("event %d = %s %s", i, ev[0], ev[1])
		}
	}
	if strings.Join(names, ",") != "response.created,response.output_item.added,response.output_item.done,response.completed" {
		t.Fatalf("events = %v", names)
	}
	if !strings.Contains(events[3][1], "echo BLOCKME") {
		t.Fatalf("completed response = %s", events[3][1])
	}
	// A text answer streams deltas.
	_, out = mockPost(t, srv.URL+"/v1/responses", `{"stream":true,"input":"hello"}`, nil)
	if !strings.Contains(out, "response.output_text.delta") {
		t.Fatalf("text stream = %s", out)
	}
}

func TestMockLLMAuxiliaryRoutes(t *testing.T) {
	_, srv := newMockServer(t)
	get := func(path string, headers map[string]string) (int, string) {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
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
	if code, body := get("/v1/models", map[string]string{"anthropic-version": "2023-06-01"}); code != 200 || !strings.Contains(body, `"type":"model"`) || !strings.Contains(body, `"has_more":false`) {
		t.Fatalf("anthropic models = %d %s", code, body)
	}
	if code, body := get("/v1/models/claude-x", map[string]string{"x-api-key": "k"}); code != 200 || !strings.Contains(body, `"id":"claude-x"`) {
		t.Fatalf("anthropic model = %d %s", code, body)
	}
	if code, body := get("/models", nil); code != 200 || !strings.Contains(body, `"object":"list"`) || !strings.Contains(body, `"mock-model"`) {
		t.Fatalf("openai models = %d %s", code, body)
	}
	if code, _ := get("/v1/responses", map[string]string{"Upgrade": "websocket", "Connection": "Upgrade"}); code != http.StatusUpgradeRequired {
		t.Fatalf("websocket = %d", code)
	}
	if code, body := mockPost(t, srv.URL+"/v1/messages/count_tokens", `{"messages":[{"role":"user","content":"abcdefgh"}]}`, nil); code != 200 || !strings.Contains(body, `"input_tokens"`) {
		t.Fatalf("count_tokens = %d %s", code, body)
	}
	if code, _ := mockPost(t, srv.URL+"/v1/messages", `{not json`, nil); code != http.StatusBadRequest {
		t.Fatalf("bad JSON = %d", code)
	}
	if code, _ := mockPost(t, srv.URL+"/v1/embeddings", `{}`, nil); code != http.StatusNotFound {
		t.Fatalf("unknown route = %d", code)
	}
	req, _ := http.NewRequest(http.MethodHead, srv.URL+"/", nil)
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != 200 {
		t.Fatalf("HEAD = %v %v", resp, err)
	}
}
