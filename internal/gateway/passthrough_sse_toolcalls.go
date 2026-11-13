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
	"strconv"
	"strings"
)

// sseToolCallMax bounds the argument bytes of the open tool calls of one
// streamed reply; past it the stream cannot be held for inspection.
const sseToolCallMax = 1 << 20

// sseToolCalls collects the tool calls of an SSE reply, so each finished
// call goes through the tool-call rules before its bytes reach the agent (as
// GAP-0098 does for the Bedrock eventstream). A call that spans events is
// assembled here from:
//   - Responses: every output item whose type is a call (function_call,
//     custom_tool_call, local_shell_call, mcp_call, computer_call and the
//     items that come after them), from response.output_item.added (open) to
//     response.output_item.done (finished), and its argument deltas;
//   - Chat Completions: choices[].delta.tool_calls (and the older
//     delta.function_call) fragments, finished by the choice's finish_reason
//     or the end of the stream;
//   - Anthropic Messages: tool_use, server_tool_use and mcp_tool_use content
//     blocks, from content_block_start to content_block_stop.
//
// A call that arrives whole in one event (Gemini functionCall, a message
// object with tool_calls, the snapshot in response.completed) is added with
// AddCalls.
type sseToolCalls struct {
	open      map[string]bool // Responses item ids in progress
	chat      map[int]*sseChatCall
	chatOrder []int
	blocks    map[int]*sseChatCall // Anthropic content blocks in progress
	done      []sseToolCall
	seen      map[string]bool // finished calls, by name and arguments
	held      int             // argument bytes of open calls
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
	return &sseToolCalls{open: map[string]bool{}, chat: map[int]*sseChatCall{}, blocks: map[int]*sseChatCall{}, seen: map[string]bool{}}
}

func (s *sseToolCalls) finished(c sseToolCall) {
	s.seen[c.Function.Name+"\x00"+c.Function.Arguments] = true
	s.done = append(s.done, c)
}

// AddCalls adds calls that arrived whole in one event, once each.
func (s *sseToolCalls) AddCalls(calls []sseToolCall) {
	for _, c := range calls {
		if !s.seen[c.Function.Name+"\x00"+c.Function.Arguments] {
			s.finished(c)
		}
	}
}

func jnodeInt(n *jnode) (int, bool) {
	if n == nil || n.kind != 'v' {
		return 0, false
	}
	i, err := strconv.Atoi(n.s)
	return i, err == nil
}

// Feed reads one SSE data payload ("[DONE]" ends the stream).
func (s *sseToolCalls) Feed(data string) {
	if data == "[DONE]" {
		s.Finish()
		return
	}
	root, err := parseJSONTree([]byte(data))
	if err != nil || root.kind != 'o' {
		return
	}
	typ := root.str("type")
	outIdx, hasOutIdx := jnodeInt(root.get("output_index"))
	if strings.HasPrefix(typ, "response.") {
		s.responses = true
		if hasOutIdx && outIdx >= s.nextIndex {
			s.nextIndex = outIdx + 1
		}
	}
	itemKey := func(id string) string {
		if id != "" {
			return id
		}
		return "output_index:" + strconv.Itoa(outIdx)
	}
	switch {
	case typ == "response.output_item.added" || typ == "response.output_item.done":
		item := root.get("item")
		if item == nil || item.kind != 'o' || !isCallType(item.str("type")) {
			break
		}
		key := itemKey(item.str("id"))
		if typ == "response.output_item.added" {
			s.open[key] = true
			break
		}
		delete(s.open, key)
		w := &textWalker{reply: true}
		w.callObject(item, "")
		for _, c := range w.calls {
			s.finished(c)
		}
		if len(s.open) == 0 && len(s.blocks) == 0 {
			s.held = 0
		}
	case strings.HasPrefix(typ, "response.") && strings.HasSuffix(typ, ".delta") && strings.Contains(typ, "_call"):
		// function_call_arguments, custom_tool_call_input, mcp_call_arguments,
		// code_interpreter_call_code ...: the item is open even if its
		// output_item.added was not seen.
		s.open[itemKey(root.str("item_id"))] = true
		if d := root.get("delta"); d != nil && d.kind == 's' {
			s.grow(len(d.s))
		}
	case typ == "response.completed" || typ == "response.failed" || typ == "response.incomplete":
		s.open = map[string]bool{}
		s.held = 0
	case typ == "content_block_start":
		idx, _ := jnodeInt(root.get("index"))
		if cb := root.get("content_block"); cb != nil && isCallType(cb.str("type")) {
			c := &sseChatCall{id: cb.str("id"), name: cb.str("name")}
			if in := cb.get("input"); in != nil && in.kind == 'o' && len(in.kids) > 0 {
				c.args.WriteString(in.json())
			}
			s.blocks[idx] = c
		}
	case typ == "content_block_delta":
		idx, _ := jnodeInt(root.get("index"))
		if d := root.get("delta"); d != nil && d.str("type") == "input_json_delta" {
			c := s.blocks[idx]
			if c == nil {
				c = &sseChatCall{}
				s.blocks[idx] = c
			}
			c.args.WriteString(d.str("partial_json"))
			s.grow(len(d.str("partial_json")))
		}
	case typ == "content_block_stop":
		idx, _ := jnodeInt(root.get("index"))
		if c := s.blocks[idx]; c != nil {
			delete(s.blocks, idx)
			tc := sseToolCall{ID: c.id, Type: "function"}
			tc.Function.Name, tc.Function.Arguments = c.name, c.args.String()
			if tc.Function.Arguments == "" {
				tc.Function.Arguments = "{}"
			}
			s.finished(tc)
			if len(s.open) == 0 && len(s.blocks) == 0 {
				s.held = 0
			}
		}
	}
	if choices := root.get("choices"); choices != nil && choices.kind == 'a' {
		for _, ch := range choices.kids {
			delta := ch.get("delta")
			if tcs := delta.get("tool_calls"); tcs != nil && tcs.kind == 'a' {
				for _, tc := range tcs.kids {
					idx, _ := jnodeInt(tc.get("index"))
					s.chatFragment(idx, tc.str("id"), tc.get("function"))
				}
			}
			if fc := delta.get("function_call"); fc != nil && fc.kind == 'o' {
				s.chatFragment(-1, "", fc)
			}
			if fr := ch.get("finish_reason"); fr != nil && fr.kind == 's' && fr.s != "" {
				s.finishChat()
			}
		}
	}
}

func (s *sseToolCalls) chatFragment(idx int, id string, fn *jnode) {
	c := s.chat[idx]
	if c == nil {
		c = &sseChatCall{}
		s.chat[idx] = c
		s.chatOrder = append(s.chatOrder, idx)
	}
	if id != "" {
		c.id = id
	}
	name, args := fn.str("name"), fn.str("arguments")
	c.name += name
	c.args.WriteString(args)
	s.grow(len(args) + len(name))
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
		s.finished(tc)
	}
	s.chat, s.chatOrder = map[int]*sseChatCall{}, nil
	if len(s.open) == 0 && len(s.blocks) == 0 {
		s.held = 0
	}
}

// Finish ends the stream: Chat Completions calls with no finish_reason are
// finished; an open Responses item or content block can no longer be
// completed.
func (s *sseToolCalls) Finish() {
	s.finishChat()
	if len(s.open) > 0 || len(s.blocks) > 0 {
		s.broken = true
	}
}

// Open reports a tool call in progress, whose bytes are held.
func (s *sseToolCalls) Open() bool {
	return len(s.open) > 0 || len(s.chatOrder) > 0 || len(s.blocks) > 0
}

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
