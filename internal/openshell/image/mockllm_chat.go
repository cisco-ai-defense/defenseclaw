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
	"time"
)

// The mock's OpenAI Chat Completions and Gemini generateContent routes serve
// the harnesses that speak those APIs (Hermes, OpenHands through LiteLLM,
// Antigravity through the Gemini SDK). Their shell tools differ in name and
// schema, so the scripted call targets whichever advertised tool is a known
// shell tool and fills its arguments from the tool's JSON schema.

// mockShellTools are the shell tool names the mock recognizes, most specific
// first.
var mockShellTools = []string{"terminal", "execute_bash", "run_command", "run_shell_command", "sys_os_shell", "bash", "Bash", "shell", "exec_command", "shell_command"}

// mockCommandKeys are the argument names that carry the command line.
var mockCommandKeys = []string{"command", "cmd", "CommandLine", "commandLine", "script"}

// mockToolSchema is the part of a JSON schema the mock reads.
type mockToolSchema struct {
	Properties map[string]struct {
		Type string        `json:"type"`
		Enum []interface{} `json:"enum"`
	} `json:"properties"`
	Required []string `json:"required"`
}

// pickShellTool returns the first known shell tool among schemas.
func pickShellTool(schemas map[string]json.RawMessage) (string, bool) {
	for _, name := range mockShellTools {
		if _, ok := schemas[name]; ok {
			return name, true
		}
	}
	return "", false
}

// shellToolArgs fills a shell tool's arguments: the command under its
// command key and a type-appropriate placeholder for every other required
// property (the first enum value when the schema has one).
func shellToolArgs(raw json.RawMessage, command string) map[string]interface{} {
	var schema mockToolSchema
	_ = json.Unmarshal(raw, &schema)
	args := map[string]interface{}{}
	key := "command"
	for _, k := range mockCommandKeys {
		if _, ok := schema.Properties[k]; ok {
			key = k
			break
		}
	}
	args[key] = command
	for _, name := range schema.Required {
		if _, set := args[name]; set {
			continue
		}
		prop := schema.Properties[name]
		switch {
		case len(prop.Enum) > 0:
			args[name] = prop.Enum[0]
		case prop.Type == "boolean":
			args[name] = false
		case prop.Type == "integer" || prop.Type == "number":
			args[name] = 30
		case prop.Type == "array":
			args[name] = []interface{}{}
		case prop.Type == "object":
			args[name] = map[string]interface{}{}
		case strings.Contains(strings.ToLower(name), "cwd") || strings.Contains(strings.ToLower(name), "dir"):
			// A working directory (Antigravity's run_command requires Cwd);
			// the scripted commands use absolute paths.
			args[name] = "/tmp"
		default:
			args[name] = "DefenseClaw hook-fire probe"
		}
	}
	return args
}

// --- OpenAI Chat Completions ---

type chatRequest struct {
	Model    string        `json:"model"`
	Stream   bool          `json:"stream"`
	Messages []chatMessage `json:"messages"`
	Tools    []struct {
		Type     string `json:"type"`
		Function struct {
			Name       string          `json:"name"`
			Parameters json.RawMessage `json:"parameters"`
		} `json:"function"`
	} `json:"tools"`
}

type chatMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

// chatText decodes string or content-part message content.
func chatText(raw json.RawMessage) string {
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
		if p.Text != "" {
			out = append(out, p.Text)
		}
	}
	return strings.Join(out, "\n")
}

// chatPosition returns the latest user prompt and the number of assistant
// turns after it (tool results arrive as role "tool").
func chatPosition(messages []chatMessage) (string, int) {
	last := -1
	for i, msg := range messages {
		if msg.Role == "user" {
			last = i
		}
	}
	if last < 0 {
		return "", 0
	}
	turns := 0
	for _, msg := range messages[last+1:] {
		if msg.Role == "assistant" {
			turns++
		}
	}
	return chatText(messages[last].Content), turns
}

func (m *mockLLM) chatCompletions(w http.ResponseWriter, r *http.Request) {
	var req chatRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 32<<20)).Decode(&req); err != nil {
		mockJSON(w, http.StatusBadRequest, map[string]interface{}{"error": map[string]string{"message": "mock: " + err.Error()}})
		return
	}
	seq := m.next()
	schemas := map[string]json.RawMessage{}
	for _, t := range req.Tools {
		if t.Function.Name != "" {
			schemas[t.Function.Name] = t.Function.Parameters
		}
	}
	prompt, turn := chatPosition(req.Messages)
	message := map[string]interface{}{"role": "assistant", "content": mockAuxText}
	finish := "stop"
	if sc := m.pick(prompt); sc != nil {
		switch {
		case turn == 0:
			if name, ok := pickShellTool(schemas); ok {
				args, _ := json.Marshal(shellToolArgs(schemas[name], sc.command))
				message = map[string]interface{}{"role": "assistant", "content": nil, "tool_calls": []interface{}{map[string]interface{}{
					"id": fmt.Sprintf("call_dcprobe_%d", seq), "type": "function",
					"function": map[string]interface{}{"name": name, "arguments": string(args)},
				}}}
				finish = "tool_calls"
				m.served(sc.match)
			} else {
				names := make([]string, 0, len(schemas))
				for name := range schemas {
					names = append(names, name)
				}
				sort.Strings(names)
				message["content"] = "mock: no shell tool among " + strings.Join(names, ",")
			}
		default:
			message["content"] = sc.done
		}
	}
	model := req.Model
	if model == "" {
		model = mockModels[0]
	}
	base := map[string]interface{}{"id": fmt.Sprintf("chatcmpl-dcprobe-%d", seq), "created": time.Now().Unix(), "model": model}
	usage := map[string]int{"prompt_tokens": 12, "completion_tokens": 5, "total_tokens": 17}
	with := func(extra map[string]interface{}) map[string]interface{} {
		out := map[string]interface{}{}
		for k, v := range base {
			out[k] = v
		}
		for k, v := range extra {
			out[k] = v
		}
		return out
	}
	if !req.Stream {
		mockJSON(w, http.StatusOK, with(map[string]interface{}{
			"object":  "chat.completion",
			"choices": []interface{}{map[string]interface{}{"index": 0, "message": message, "finish_reason": finish}},
			"usage":   usage,
		}))
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	data := func(v interface{}) {
		raw, _ := json.Marshal(v)
		_, _ = fmt.Fprintf(w, "data: %s\n\n", raw)
		if flusher != nil {
			flusher.Flush()
		}
	}
	chunk := func(delta map[string]interface{}, finish interface{}) map[string]interface{} {
		return with(map[string]interface{}{
			"object":  "chat.completion.chunk",
			"choices": []interface{}{map[string]interface{}{"index": 0, "delta": delta, "finish_reason": finish}},
		})
	}
	data(chunk(map[string]interface{}{"role": "assistant", "content": ""}, nil))
	if calls, ok := message["tool_calls"].([]interface{}); ok {
		call := calls[0].(map[string]interface{})
		fn := call["function"].(map[string]interface{})
		data(chunk(map[string]interface{}{"tool_calls": []interface{}{map[string]interface{}{
			"index": 0, "id": call["id"], "type": "function",
			"function": map[string]interface{}{"name": fn["name"], "arguments": ""},
		}}}, nil))
		for _, part := range chunks(fn["arguments"].(string), 32) {
			data(chunk(map[string]interface{}{"tool_calls": []interface{}{map[string]interface{}{
				"index": 0, "function": map[string]interface{}{"arguments": part},
			}}}, nil))
		}
	} else {
		for _, part := range chunks(message["content"].(string), 24) {
			data(chunk(map[string]interface{}{"content": part}, nil))
		}
	}
	final := chunk(map[string]interface{}{}, finish)
	final["usage"] = usage
	data(final)
	_, _ = io.WriteString(w, "data: [DONE]\n\n")
	if flusher != nil {
		flusher.Flush()
	}
}

// --- Gemini generateContent ---

type geminiRequest struct {
	Contents []geminiContent `json:"contents"`
	Tools    []struct {
		FunctionDeclarations []struct {
			Name                 string          `json:"name"`
			Parameters           json.RawMessage `json:"parameters"`
			ParametersJSONSchema json.RawMessage `json:"parametersJsonSchema"`
		} `json:"functionDeclarations"`
	} `json:"tools"`
}

type geminiContent struct {
	Role  string `json:"role"`
	Parts []struct {
		Text             *string         `json:"text"`
		FunctionCall     json.RawMessage `json:"functionCall"`
		FunctionResponse json.RawMessage `json:"functionResponse"`
	} `json:"parts"`
}

// geminiPosition returns the latest user text prompt (function responses
// arrive as user parts without text) and the model turns after it.
func geminiPosition(contents []geminiContent) (string, int) {
	last := -1
	for i, c := range contents {
		if c.Role != "user" {
			continue
		}
		for _, p := range c.Parts {
			if p.Text != nil && len(p.FunctionResponse) == 0 {
				last = i
				break
			}
		}
	}
	if last < 0 {
		return "", 0
	}
	var texts []string
	for _, p := range contents[last].Parts {
		if p.Text != nil {
			texts = append(texts, *p.Text)
		}
	}
	turns := 0
	for _, c := range contents[last+1:] {
		if c.Role == "model" {
			turns++
		}
	}
	return strings.Join(texts, "\n"), turns
}

func (m *mockLLM) geminiGenerate(w http.ResponseWriter, r *http.Request, stream bool) {
	var req geminiRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 32<<20)).Decode(&req); err != nil {
		mockJSON(w, http.StatusBadRequest, map[string]interface{}{"error": map[string]interface{}{"code": 400, "message": "mock: " + err.Error(), "status": "INVALID_ARGUMENT"}})
		return
	}
	m.next()
	schemas := map[string]json.RawMessage{}
	for _, t := range req.Tools {
		for _, fd := range t.FunctionDeclarations {
			schema := fd.Parameters
			if len(schema) == 0 {
				schema = fd.ParametersJSONSchema
			}
			schemas[fd.Name] = schema
		}
	}
	prompt, turn := geminiPosition(req.Contents)
	parts := []interface{}{map[string]interface{}{"text": mockAuxText}}
	if sc := m.pick(prompt); sc != nil {
		switch {
		case turn == 0:
			if name, ok := pickShellTool(schemas); ok {
				parts = []interface{}{map[string]interface{}{"functionCall": map[string]interface{}{"name": name, "args": shellToolArgs(schemas[name], sc.command)}}}
				m.served(sc.match)
			}
		default:
			parts = []interface{}{map[string]interface{}{"text": sc.done}}
		}
	}
	resp := map[string]interface{}{
		"candidates": []interface{}{map[string]interface{}{
			"content": map[string]interface{}{"role": "model", "parts": parts}, "finishReason": "STOP", "index": 0,
		}},
		"usageMetadata": map[string]int{"promptTokenCount": 12, "candidatesTokenCount": 5, "totalTokenCount": 17},
		"modelVersion":  mockModels[0],
	}
	if !stream {
		mockJSON(w, http.StatusOK, resp)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	raw, _ := json.Marshal(resp)
	_, _ = fmt.Fprintf(w, "data: %s\r\n\r\n", raw)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}
