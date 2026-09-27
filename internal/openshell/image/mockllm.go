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
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// mockLLM is the hook-fire probe's built-in model endpoint: a scripted
// Anthropic Messages and OpenAI Responses server the probe serves itself, so
// an image can be verified without a model, a key or network access. Each
// scenario answers the first request of its prompt with exactly one shell
// tool call and the request that carries the tool result with a closing
// text; every other request (title generation, quota probes, classifiers)
// gets a plain text answer that burns no scripted turn.
//
// Routes: POST /v1/messages (streaming and not), POST
// /v1/messages/count_tokens, POST /v1/responses and /responses (streaming
// and not), GET /v1/models[/<id>] and /models, and HEAD on any path (Claude
// Code warms the connection up). Anything else is a 404 JSON error.
type mockLLM struct {
	scenarios []mockScenario

	mu  sync.Mutex
	seq int
	// toolCalls counts the scripted tool calls served per scenario.
	toolCalls map[string]int
}

// mockScenario is one scripted conversation.
type mockScenario struct {
	// match selects the scenario: a substring of the latest user prompt.
	match string
	// command is the shell command of the scenario's one tool call.
	command string
	// done is the closing text once the tool result (or refusal) is back.
	done string
}

// mockAuxText answers every request outside a scripted turn.
const mockAuxText = "DefenseClaw hook-fire probe"

// mockModels are listed by GET /v1/models.
var mockModels = []string{"mock-model", "claude-sonnet-4-5", "claude-haiku-4-5"}

func newMockLLM(scenarios ...mockScenario) *mockLLM {
	return &mockLLM{scenarios: scenarios, toolCalls: map[string]int{}}
}

// toolCallsServed reports how many scripted tool calls each scenario got.
func (m *mockLLM) toolCallsServed() map[string]int {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]int, len(m.toolCalls))
	for k, v := range m.toolCalls {
		out[k] = v
	}
	return out
}

func (m *mockLLM) next() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seq++
	return m.seq
}

func (m *mockLLM) served(match string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.toolCalls[match]++
}

// pick returns the scenario whose match occurs in prompt, or nil.
func (m *mockLLM) pick(prompt string) *mockScenario {
	if prompt == "" {
		return nil
	}
	for i := range m.scenarios {
		if strings.Contains(prompt, m.scenarios[i].match) {
			return &m.scenarios[i]
		}
	}
	return nil
}

func (m *mockLLM) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimSuffix(r.URL.Path, "/")
	switch {
	case r.Method == http.MethodHead:
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodGet && strings.EqualFold(r.Header.Get("Upgrade"), "websocket"):
		// Codex tries a Responses websocket first and falls back to HTTP.
		mockJSON(w, http.StatusUpgradeRequired, map[string]interface{}{"error": map[string]string{"message": "mock: websocket unsupported"}})
	case r.Method == http.MethodGet && (path == "/v1/models" || path == "/models"):
		m.models(w, r, "")
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/v1/models/"):
		m.models(w, r, strings.TrimPrefix(path, "/v1/models/"))
	case r.Method == http.MethodPost && path == "/v1/messages/count_tokens":
		body, _ := io.ReadAll(io.LimitReader(r.Body, 32<<20))
		mockJSON(w, http.StatusOK, map[string]int{"input_tokens": max(1, len(body)/4)})
	case r.Method == http.MethodPost && path == "/v1/messages":
		m.messages(w, r)
	case r.Method == http.MethodPost && (path == "/v1/responses" || path == "/responses"):
		m.responses(w, r)
	default:
		mockJSON(w, http.StatusNotFound, map[string]interface{}{
			"type":  "error",
			"error": map[string]string{"type": "not_found_error", "message": "mock: " + r.Method + " " + r.URL.Path},
		})
	}
}

func (m *mockLLM) models(w http.ResponseWriter, r *http.Request, id string) {
	anthropic := r.Header.Get("anthropic-version") != "" || r.Header.Get("x-api-key") != ""
	entry := func(id string) map[string]interface{} {
		if anthropic {
			return map[string]interface{}{"type": "model", "id": id, "display_name": id, "created_at": "2026-01-01T00:00:00Z"}
		}
		return map[string]interface{}{"id": id, "object": "model", "created": 1767225600, "owned_by": "defenseclaw"}
	}
	if id != "" {
		mockJSON(w, http.StatusOK, entry(id))
		return
	}
	data := make([]map[string]interface{}, 0, len(mockModels))
	for _, id := range mockModels {
		data = append(data, entry(id))
	}
	if anthropic {
		mockJSON(w, http.StatusOK, map[string]interface{}{"data": data, "has_more": false, "first_id": mockModels[0], "last_id": mockModels[len(mockModels)-1]})
		return
	}
	mockJSON(w, http.StatusOK, map[string]interface{}{"object": "list", "data": data, "models": []interface{}{}})
}

// --- Anthropic Messages ---

type anthropicRequest struct {
	Model    string             `json:"model"`
	Stream   bool               `json:"stream"`
	Messages []anthropicMessage `json:"messages"`
	Tools    []struct {
		Name string `json:"name"`
	} `json:"tools"`
}

type anthropicMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

type anthropicBlock struct {
	Type  string                 `json:"type"`
	Text  string                 `json:"text,omitempty"`
	ID    string                 `json:"id,omitempty"`
	Name  string                 `json:"name,omitempty"`
	Input map[string]interface{} `json:"input,omitempty"`
}

// anthropicBlocks decodes string or block-list content.
func anthropicBlocks(raw json.RawMessage) []anthropicBlock {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return []anthropicBlock{{Type: "text", Text: text}}
	}
	var blocks []anthropicBlock
	_ = json.Unmarshal(raw, &blocks)
	return blocks
}

// anthropicPosition returns the latest real user prompt (a user message that
// is not only tool results) and the number of assistant turns after it.
func anthropicPosition(messages []anthropicMessage) (string, int) {
	last := -1
	for i, msg := range messages {
		if msg.Role != "user" {
			continue
		}
		blocks := anthropicBlocks(msg.Content)
		toolResultsOnly := len(blocks) > 0
		for _, b := range blocks {
			toolResultsOnly = toolResultsOnly && b.Type == "tool_result"
		}
		if !toolResultsOnly {
			last = i
		}
	}
	if last < 0 {
		return "", 0
	}
	var texts []string
	for _, b := range anthropicBlocks(messages[last].Content) {
		if b.Type == "text" {
			texts = append(texts, b.Text)
		}
	}
	turns := 0
	for _, msg := range messages[last+1:] {
		if msg.Role == "assistant" {
			turns++
		}
	}
	return strings.Join(texts, "\n"), turns
}

func (m *mockLLM) messages(w http.ResponseWriter, r *http.Request) {
	var req anthropicRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 32<<20)).Decode(&req); err != nil {
		mockJSON(w, http.StatusBadRequest, map[string]interface{}{"type": "error", "error": map[string]string{"type": "invalid_request_error", "message": "mock: " + err.Error()}})
		return
	}
	seq := m.next()
	tools := map[string]bool{}
	for _, t := range req.Tools {
		tools[t.Name] = true
	}
	prompt, turn := anthropicPosition(req.Messages)
	blocks, stop := []anthropicBlock{{Type: "text", Text: mockAuxText}}, "end_turn"
	if sc := m.pick(prompt); sc != nil {
		switch {
		case turn == 0 && tools["Bash"]:
			// A request that cannot call the tool (title generation, quota
			// probes, classifiers) never burns the scripted tool turn.
			blocks = []anthropicBlock{{
				Type: "tool_use", ID: fmt.Sprintf("toolu_dcprobe_%d", seq), Name: "Bash",
				Input: map[string]interface{}{"command": sc.command, "description": "DefenseClaw hook-fire probe"},
			}}
			stop = "tool_use"
			m.served(sc.match)
		case turn > 0:
			blocks = []anthropicBlock{{Type: "text", Text: sc.done}}
		}
	}
	model := req.Model
	if model == "" {
		model = mockModels[1]
	}
	id := fmt.Sprintf("msg_dcprobe_%d", seq)
	usage := map[string]int{"input_tokens": 12, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0, "output_tokens": 5}
	if !req.Stream {
		mockJSON(w, http.StatusOK, map[string]interface{}{
			"id": id, "type": "message", "role": "assistant", "model": model,
			"content": blocks, "stop_reason": stop, "stop_sequence": nil, "usage": usage,
		})
		return
	}
	sse := newSSE(w)
	sse.event("message_start", map[string]interface{}{"type": "message_start", "message": map[string]interface{}{
		"id": id, "type": "message", "role": "assistant", "model": model, "content": []interface{}{},
		"stop_reason": nil, "stop_sequence": nil, "usage": map[string]int{"input_tokens": 12, "output_tokens": 1},
	}})
	sse.event("ping", map[string]string{"type": "ping"})
	for i, b := range blocks {
		switch b.Type {
		case "tool_use":
			sse.event("content_block_start", map[string]interface{}{"type": "content_block_start", "index": i,
				"content_block": map[string]interface{}{"type": "tool_use", "id": b.ID, "name": b.Name, "input": map[string]interface{}{}}})
			input, _ := json.Marshal(b.Input)
			for _, part := range chunks(string(input), 32) {
				sse.event("content_block_delta", map[string]interface{}{"type": "content_block_delta", "index": i,
					"delta": map[string]string{"type": "input_json_delta", "partial_json": part}})
			}
		default:
			sse.event("content_block_start", map[string]interface{}{"type": "content_block_start", "index": i,
				"content_block": map[string]string{"type": "text", "text": ""}})
			for _, part := range chunks(b.Text, 24) {
				sse.event("content_block_delta", map[string]interface{}{"type": "content_block_delta", "index": i,
					"delta": map[string]string{"type": "text_delta", "text": part}})
			}
		}
		sse.event("content_block_stop", map[string]interface{}{"type": "content_block_stop", "index": i})
	}
	sse.event("message_delta", map[string]interface{}{"type": "message_delta",
		"delta": map[string]interface{}{"stop_reason": stop, "stop_sequence": nil}, "usage": map[string]int{"output_tokens": 5}})
	sse.event("message_stop", map[string]string{"type": "message_stop"})
}

// --- OpenAI Responses ---

type responsesRequest struct {
	Model  string          `json:"model"`
	Stream bool            `json:"stream"`
	Input  json.RawMessage `json:"input"`
	Tools  []struct {
		Type     string `json:"type"`
		Name     string `json:"name"`
		Function struct {
			Name string `json:"name"`
		} `json:"function"`
	} `json:"tools"`
}

type responsesItem struct {
	Type    string          `json:"type"`
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

// responsesModelItems are output items the model emitted.
var responsesModelItems = map[string]bool{"function_call": true, "custom_tool_call": true, "local_shell_call": true, "web_search_call": true}

func responsesText(raw json.RawMessage) string {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	_ = json.Unmarshal(raw, &parts)
	var out []string
	for _, p := range parts {
		switch p.Type {
		case "input_text", "output_text", "text":
			out = append(out, p.Text)
		}
	}
	return strings.Join(out, "\n")
}

// responsesPosition returns the latest user prompt (Codex's environment
// context message is skipped unless it is the last item) and the number of
// model items after it.
func responsesPosition(raw json.RawMessage) (string, int) {
	var items []responsesItem
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text, 0
	}
	_ = json.Unmarshal(raw, &items)
	last := -1
	for i, it := range items {
		if (it.Type == "" || it.Type == "message") && it.Role == "user" {
			if strings.Contains(responsesText(it.Content), "<environment_context>") && i+1 < len(items) {
				continue
			}
			last = i
		}
	}
	if last < 0 {
		return "", 0
	}
	turns := 0
	for _, it := range items[last+1:] {
		if responsesModelItems[it.Type] || ((it.Type == "" || it.Type == "message") && it.Role == "assistant") {
			turns++
		}
	}
	return responsesText(items[last].Content), turns
}

// responsesShellCall renders command against the shell tool the request
// advertises (the tool names change between Codex releases).
func responsesShellCall(command string, tools map[string]string, seq int) map[string]interface{} {
	callID := fmt.Sprintf("call_dcprobe_%d", seq)
	args := func(v interface{}) string {
		raw, _ := json.Marshal(v)
		return string(raw)
	}
	switch {
	case tools["shell_command"] != "":
		return map[string]interface{}{"type": "function_call", "name": "shell_command", "call_id": callID,
			"arguments": args(map[string]interface{}{"command": command, "timeout_ms": 30000})}
	case tools["exec_command"] != "":
		return map[string]interface{}{"type": "function_call", "name": "exec_command", "call_id": callID,
			"arguments": args(map[string]interface{}{"cmd": command, "yield_time_ms": 10000})}
	case tools["shell"] == "function":
		return map[string]interface{}{"type": "function_call", "name": "shell", "call_id": callID,
			"arguments": args(map[string]interface{}{"command": []string{"bash", "-lc", command}, "timeout_ms": 30000})}
	case tools["local_shell"] != "":
		return map[string]interface{}{"type": "local_shell_call", "call_id": callID, "status": "completed",
			"action": map[string]interface{}{"type": "exec", "command": []string{"bash", "-lc", command}, "timeout_ms": 30000}}
	}
	return nil
}

func responsesMessage(text string, seq int) map[string]interface{} {
	return map[string]interface{}{"type": "message", "role": "assistant", "id": fmt.Sprintf("msg_dcprobe_%d", seq), "status": "completed",
		"content": []interface{}{map[string]interface{}{"type": "output_text", "text": text, "annotations": []interface{}{}}}}
}

func (m *mockLLM) responses(w http.ResponseWriter, r *http.Request) {
	var req responsesRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 32<<20)).Decode(&req); err != nil {
		mockJSON(w, http.StatusBadRequest, map[string]interface{}{"error": map[string]string{"message": "mock: " + err.Error()}})
		return
	}
	seq := m.next()
	tools := map[string]string{}
	for _, t := range req.Tools {
		name := t.Name
		if name == "" {
			name = t.Function.Name
		}
		if name == "" {
			name = t.Type
		}
		tools[name] = t.Type
	}
	prompt, turn := responsesPosition(req.Input)
	items := []map[string]interface{}{responsesMessage(mockAuxText, seq)}
	if sc := m.pick(prompt); sc != nil {
		switch {
		case turn == 0:
			if call := responsesShellCall(sc.command, tools, seq); call != nil {
				items = []map[string]interface{}{call}
				m.served(sc.match)
			} else {
				names := make([]string, 0, len(tools))
				for name := range tools {
					names = append(names, name)
				}
				sort.Strings(names)
				items = []map[string]interface{}{responsesMessage("mock: no shell tool among "+strings.Join(names, ","), seq)}
			}
		default:
			items = []map[string]interface{}{responsesMessage(sc.done, seq)}
		}
	}
	model := req.Model
	if model == "" {
		model = mockModels[0]
	}
	base := map[string]interface{}{"id": fmt.Sprintf("resp_dcprobe_%d", seq), "object": "response", "created_at": time.Now().Unix(), "model": model}
	usage := map[string]interface{}{"input_tokens": 12, "input_tokens_details": map[string]int{"cached_tokens": 0}, "output_tokens": 5,
		"output_tokens_details": map[string]int{"reasoning_tokens": 0}, "total_tokens": 17}
	response := func(status string, output interface{}) map[string]interface{} {
		out := map[string]interface{}{"status": status, "output": output}
		for k, v := range base {
			out[k] = v
		}
		if status == "completed" {
			out["usage"] = usage
		}
		return out
	}
	if !req.Stream {
		mockJSON(w, http.StatusOK, response("completed", items))
		return
	}
	sse := newSSE(w)
	n := 0
	emit := func(ev map[string]interface{}) {
		ev["sequence_number"] = n
		n++
		sse.event(ev["type"].(string), ev)
	}
	emit(map[string]interface{}{"type": "response.created", "response": response("in_progress", []interface{}{})})
	for idx, item := range items {
		added := map[string]interface{}{}
		for k, v := range item {
			added[k] = v
		}
		if item["type"] == "message" {
			added["content"] = []interface{}{}
			added["status"] = "in_progress"
		}
		emit(map[string]interface{}{"type": "response.output_item.added", "output_index": idx, "item": added})
		if item["type"] == "message" {
			text := item["content"].([]interface{})[0].(map[string]interface{})["text"].(string)
			for _, part := range chunks(text, 24) {
				emit(map[string]interface{}{"type": "response.output_text.delta", "item_id": item["id"], "output_index": idx, "content_index": 0, "delta": part})
			}
		}
		emit(map[string]interface{}{"type": "response.output_item.done", "output_index": idx, "item": item})
	}
	emit(map[string]interface{}{"type": "response.completed", "response": response("completed", items)})
}

// --- helpers ---

type sseWriter struct {
	w http.ResponseWriter
	f http.Flusher
}

func newSSE(w http.ResponseWriter) *sseWriter {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	f, _ := w.(http.Flusher)
	return &sseWriter{w: w, f: f}
}

func (s *sseWriter) event(name string, data interface{}) {
	raw, _ := json.Marshal(data)
	_, _ = fmt.Fprintf(s.w, "event: %s\ndata: %s\n\n", name, raw)
	if s.f != nil {
		s.f.Flush()
	}
}

func mockJSON(w http.ResponseWriter, status int, v interface{}) {
	raw, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}

// chunks splits s into pieces of at most n bytes (one empty piece for "").
func chunks(s string, n int) []string {
	if s == "" {
		return []string{""}
	}
	var out []string
	for len(s) > n {
		out = append(out, s[:n])
		s = s[n:]
	}
	return append(out, s)
}
