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

package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// sseToolCallMax bounds the argument bytes of the open tool calls of one
// streamed reply; past it the stream cannot be held for inspection.
const sseToolCallMax = 1 << 20

// passthroughWireProvider is the provider whose wire format a passthrough
// reply is read in. Bedrock Runtime's OpenAI-compatible API (/openai/v1/...
// on a bedrock-runtime host: GPT-5.6 Luna for Codex, OpenCode, Copilot CLI
// and Hermes, GAP-0187) answers in the OpenAI shapes, not in Converse or
// InvokeModel ones.
func passthroughWireProvider(provider, path string) string {
	if provider == "bedrock" && strings.HasPrefix(path, "/openai/") {
		return "openai"
	}
	return provider
}

// sseToolCalls collects the tool calls of an OpenAI-shaped SSE reply, so
// each finished call goes through the tool-call rules before its bytes
// reach the agent (as GAP-0098 does for the Bedrock eventstream):
//   - Responses: function_call, custom_tool_call, local_shell_call and
//     mcp_call items, from response.output_item.added (open) to
//     response.output_item.done (finished);
//   - Chat Completions: choices[].delta.tool_calls fragments, finished by
//     the choice's finish_reason or the end of the stream.
type sseToolCalls struct {
	open      map[string]bool // Responses item ids in progress
	chat      map[int]*sseChatCall
	chatOrder []int
	done      []sseToolCall
	held      int // argument bytes of open calls
	broken    bool
	responses bool // a Responses event was seen
	nextIndex int  // next free Responses output_index
}

type sseToolCall struct {
	ID       string `json:"id,omitempty"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type sseChatCall struct {
	id, name string
	args     strings.Builder
}

func newSSEToolCalls() *sseToolCalls {
	return &sseToolCalls{open: map[string]bool{}, chat: map[int]*sseChatCall{}}
}

// sseResponsesToolItems are the Responses output item types that run a tool.
var sseResponsesToolItems = map[string]bool{"function_call": true, "custom_tool_call": true, "local_shell_call": true, "mcp_call": true}

// Feed reads one SSE data payload ("[DONE]" ends the stream).
func (s *sseToolCalls) Feed(data string) {
	if data == "[DONE]" {
		s.Finish()
		return
	}
	var ev struct {
		Type        string          `json:"type"`
		OutputIndex *int            `json:"output_index"`
		Item        json.RawMessage `json:"item"`
		Delta       json.RawMessage `json:"delta"`
		Choices     []struct {
			Delta struct {
				ToolCalls []struct {
					Index    int    `json:"index"`
					ID       string `json:"id"`
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"delta"`
			FinishReason *string `json:"finish_reason"`
		} `json:"choices"`
	}
	if json.Unmarshal([]byte(data), &ev) != nil {
		return
	}
	if strings.HasPrefix(ev.Type, "response.") {
		s.responses = true
		if ev.OutputIndex != nil && *ev.OutputIndex >= s.nextIndex {
			s.nextIndex = *ev.OutputIndex + 1
		}
	}
	switch ev.Type {
	case "response.output_item.added", "response.output_item.done":
		var item struct {
			ID        string          `json:"id"`
			Type      string          `json:"type"`
			CallID    string          `json:"call_id"`
			Name      string          `json:"name"`
			Arguments string          `json:"arguments"`
			Input     string          `json:"input"`
			Action    json.RawMessage `json:"action"`
		}
		if json.Unmarshal(ev.Item, &item) != nil || !sseResponsesToolItems[item.Type] {
			return
		}
		if ev.Type == "response.output_item.added" {
			s.open[item.ID] = true
			return
		}
		delete(s.open, item.ID)
		c := sseToolCall{ID: item.CallID, Type: "function"}
		c.Function.Name, c.Function.Arguments = item.Name, item.Arguments
		switch item.Type {
		case "custom_tool_call":
			c.Function.Arguments = item.Input
		case "local_shell_call":
			c.Function.Name, c.Function.Arguments = "local_shell", string(item.Action)
		}
		s.done = append(s.done, c)
		if len(s.open) == 0 {
			s.held = 0
		}
	case "response.function_call_arguments.delta", "response.custom_tool_call_input.delta":
		var d string
		_ = json.Unmarshal(ev.Delta, &d)
		s.grow(len(d))
	case "response.completed", "response.failed", "response.incomplete":
		s.open = map[string]bool{}
		s.held = 0
	}
	for _, ch := range ev.Choices {
		for _, tc := range ch.Delta.ToolCalls {
			c := s.chat[tc.Index]
			if c == nil {
				c = &sseChatCall{}
				s.chat[tc.Index] = c
				s.chatOrder = append(s.chatOrder, tc.Index)
			}
			if tc.ID != "" {
				c.id = tc.ID
			}
			c.name += tc.Function.Name
			c.args.WriteString(tc.Function.Arguments)
			s.grow(len(tc.Function.Arguments) + len(tc.Function.Name))
		}
		if ch.FinishReason != nil && *ch.FinishReason != "" {
			s.finishChat()
		}
	}
}

func (s *sseToolCalls) grow(n int) {
	s.held += n
	if s.held > sseToolCallMax {
		s.broken = true
	}
}

func (s *sseToolCalls) finishChat() {
	for _, i := range s.chatOrder {
		c := s.chat[i]
		tc := sseToolCall{ID: c.id, Type: "function"}
		tc.Function.Name, tc.Function.Arguments = c.name, c.args.String()
		s.done = append(s.done, tc)
	}
	s.chat, s.chatOrder = map[int]*sseChatCall{}, nil
	if len(s.open) == 0 {
		s.held = 0
	}
}

// Finish ends the stream: Chat Completions calls with no finish_reason are
// finished; an open Responses item can no longer be completed.
func (s *sseToolCalls) Finish() {
	s.finishChat()
	if len(s.open) > 0 {
		s.broken = true
	}
}

// Open reports a tool call in progress, whose bytes are held.
func (s *sseToolCalls) Open() bool { return len(s.open) > 0 || len(s.chatOrder) > 0 }

// Broken reports a stream whose tool calls cannot be inspected (too large,
// or cut inside a call).
func (s *sseToolCalls) Broken() bool { return s.broken }

// Take returns the finished calls since the last Take, in the tool_calls
// shape inspectToolCalls reads, or nil.
func (s *sseToolCalls) Take() json.RawMessage {
	if len(s.done) == 0 {
		return nil
	}
	raw, _ := json.Marshal(s.done)
	s.done = nil
	return raw
}

// writeSSEBlockTail ends an OpenAI-shaped stream that was already partly
// sent with msg as the last assistant text, so the agent shows the block
// instead of a cut stream: a Responses message item and response.completed,
// or a Chat Completions chunk with finish_reason "stop" and [DONE].
func (s *sseToolCalls) writeSSEBlockTail(w http.ResponseWriter, model, msg string) {
	if s.responses {
		item := map[string]any{"id": "msg_blocked", "type": "message", "role": "assistant", "status": "completed",
			"content": []any{map[string]any{"type": "output_text", "text": msg, "annotations": []any{}}}}
		for _, ev := range []map[string]any{
			{"type": "response.output_item.added", "output_index": s.nextIndex, "item": item},
			{"type": "response.output_item.done", "output_index": s.nextIndex, "item": item},
			{"type": "response.completed", "response": map[string]any{"id": "resp_blocked", "object": "response", "model": model,
				"status": "completed", "output": []any{item}}},
		} {
			raw, _ := json.Marshal(ev)
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev["type"], raw)
		}
	} else {
		raw, _ := json.Marshal(map[string]any{"object": "chat.completion.chunk", "model": model,
			"choices": []any{map[string]any{"index": 0, "delta": map[string]any{"content": msg}, "finish_reason": "stop"}}})
		fmt.Fprintf(w, "data: %s\n\ndata: [DONE]\n\n", raw)
	}
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}
