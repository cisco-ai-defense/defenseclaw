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
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
)

// sseToolCallMax bounds the argument bytes of the open tool calls of one
// streamed reply; past it the stream cannot be held for inspection.
const sseToolCallMax = 1 << 20

// serverCallType reports a call item the provider runs itself (web search,
// file search, code interpreter, image generation, an MCP server it calls, an
// Anthropic server or MCP tool). The agent does not execute such a call, so
// the stream is not held for it: its progress events and keep-alives go
// through at once. Its finished call is still read by the tool-call rules, and
// every text it returns is inspected like any other reply text (GAP-0249).
func serverCallType(t string) bool {
	switch t {
	case "web_search_call", "file_search_call", "code_interpreter_call", "image_generation_call", "mcp_call",
		"server_tool_use", "mcp_tool_use":
		return true
	}
	return false
}

// callTypeOfEvent is the call item type a Responses event names:
// response.code_interpreter_call_code.delta is a code_interpreter_call.
func callTypeOfEvent(typ string) string {
	rest := strings.TrimPrefix(typ, "response.")
	if i := strings.Index(rest, "_call"); i >= 0 {
		return rest[:i+len("_call")]
	}
	return ""
}

// sseToolCalls collects the tool calls of an SSE reply, so each finished
// call goes through the tool-call rules before its bytes reach the agent (as
// GAP-0098 does for the Bedrock eventstream). A call that spans events is
// assembled here from:
//   - Responses: every output item whose type is a call (function_call,
//     custom_tool_call, local_shell_call, mcp_call, computer_call and the
//     items that come after them), from response.output_item.added (open) to
//     response.output_item.done (finished). Its argument deltas and the full
//     text of its *_call_*.done event are kept: an item that never gets its
//     output_item.done is judged with them at response.completed (failed,
//     incomplete) or at the end of the stream (GAP-0321), and so is a delta
//     text that differs from the finished item. An event with an item id
//     names that item only; output_index finds the item of an event that has
//     none. Text that comes for an item after it was judged is judged with
//     the item's name at the end and never reopens it;
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
	open map[string]*sseRespCall // Responses call items in progress, by item id or output index
	// byIdx is the key of the open item at an output_index, and closedIdx
	// the key of the last item closed there: an event without an item id
	// finds its item through them.
	byIdx, closedIdx map[int]string
	// closed are the Responses items already judged, by key (at most
	// sseRespClosedMax); late lists the ones that got text since.
	closed  map[string]*sseRespCall
	late    []*sseRespCall
	openSeq int // the next open item's place in the order items open
	// respHeld is the text the Responses items keep (open items, items a
	// response ended and late text); held is the Chat Completions and
	// Anthropic call text. Together they are bounded by sseToolCallMax.
	respHeld  int
	chat      map[int]*sseChatCall
	chatOrder []int
	blocks    map[int]*sseChatCall // Anthropic content blocks in progress
	// serverBlocks are the Anthropic server and MCP tool blocks in progress:
	// read when they end, never held.
	serverBlocks map[int]*sseChatCall
	done         []sseToolCall
	seen         map[string]bool // finished calls, by name and arguments
	held         int             // argument bytes of open calls
	broken       bool
	responses    bool // a Responses event was seen
	nextIndex    int  // next free Responses output_index
	// maxValues is the value cap of an event (guardrail.max_body_values).
	maxValues int
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

// sseRespCall is a Responses call item: what its added item, its argument
// deltas and its *_call_*.done event said.
type sseRespCall struct {
	key, id, name string
	typ           string // the item type: function_call, custom_tool_call ...
	outIdx        int    // output_index, -1 when unknown
	seq           int    // the order the item opened in
	args          strings.Builder
	// doneText is the text of the item's *_call_*.done event when it
	// differs from the deltas (when there were none it is in args).
	doneText string
	late     bool // judged, and text came after: judged again at the end
}

// sseRespClosedMax bounds the judged items a stream remembers. Past it they
// are forgotten: an event for a forgotten item opens it again, and an item
// still open at the end makes the stream Broken (the fail mode).
const sseRespClosedMax = 1 << 14

// sseRespIdxKey is the key of an item known only by its output_index.
const sseRespIdxKey = "output_index:"

// texts are the argument texts the item is judged with: its deltas, and the
// text of its .done event when that differs.
func (c *sseRespCall) texts() []string {
	var out []string
	if a := c.args.String(); a != "" {
		out = append(out, a)
	}
	if c.doneText != "" && (len(out) == 0 || out[0] != c.doneText) {
		out = append(out, c.doneText)
	}
	return out
}

func (c *sseRespCall) stored() int { return c.args.Len() + len(c.doneText) }

func newSSEToolCalls(maxValues int) *sseToolCalls {
	return &sseToolCalls{maxValues: maxValues, open: map[string]*sseRespCall{}, byIdx: map[int]string{}, closedIdx: map[int]string{},
		closed: map[string]*sseRespCall{}, chat: map[int]*sseChatCall{}, blocks: map[int]*sseChatCall{},
		serverBlocks: map[int]*sseChatCall{}, seen: map[string]bool{}}
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

// respItem is the Responses item of key: the open one, a judged one (whose
// new text is late), or a new open item.
func (s *sseToolCalls) respItem(key string, outIdx int) *sseRespCall {
	if c := s.open[key]; c != nil {
		return c
	}
	if c := s.closed[key]; c != nil {
		if !c.late {
			c.late = true
			s.late = append(s.late, c)
		}
		return c
	}
	c := &sseRespCall{key: key, outIdx: outIdx, seq: s.openSeq}
	s.openSeq++
	s.open[key] = c
	if outIdx >= 0 {
		s.byIdx[outIdx] = key
	}
	return c
}

// rekey gives the open item known only by its output_index the item id a
// later event of it carries.
func (s *sseToolCalls) rekey(c *sseRespCall, id string) {
	delete(s.open, c.key)
	c.key = id
	s.open[id] = c
	if c.outIdx >= 0 {
		s.byIdx[c.outIdx] = id
	}
}

// closeResp moves the open item c to the judged ones. keep keeps its text
// (a late part is judged with it); else the text is let go.
func (s *sseToolCalls) closeResp(c *sseRespCall, keep bool) {
	delete(s.open, c.key)
	if c.outIdx >= 0 {
		if s.byIdx[c.outIdx] == c.key {
			delete(s.byIdx, c.outIdx)
		}
		s.closedIdx[c.outIdx] = c.key
	}
	if !keep {
		s.respHeld -= c.stored()
		c.args.Reset()
		c.doneText = ""
	}
	if len(s.closed) >= sseRespClosedMax {
		// Forget the judged items (their late text was judged or goes with
		// them): an event of one opens it again.
		for _, l := range s.late {
			s.judgeResp(l)
		}
		for _, l := range s.closed {
			s.respHeld -= l.stored()
		}
		s.closed, s.closedIdx, s.late = map[string]*sseRespCall{}, map[int]string{}, nil
	}
	s.closed[c.key] = c
}

// unlate takes the judged item c off the late list.
func (s *sseToolCalls) unlate(c *sseRespCall) {
	c.late = false
	for i := len(s.late) - 1; i >= 0; i-- {
		if s.late[i] == c {
			s.late = append(s.late[:i:i], s.late[i+1:]...)
			return
		}
	}
}

// dropClosed forgets the judged item c, after its late text is judged.
func (s *sseToolCalls) dropClosed(c *sseRespCall) {
	if c.late {
		s.judgeResp(c)
		s.unlate(c)
	}
	s.respHeld -= c.stored()
	delete(s.closed, c.key)
	if c.outIdx >= 0 && s.closedIdx[c.outIdx] == c.key {
		delete(s.closedIdx, c.outIdx)
	}
}

// judgeResp adds the argument texts of the item c that no finished call
// carries, as calls of its name (of its type when it has none, as
// textWalker.callObject names a call).
func (s *sseToolCalls) judgeResp(c *sseRespCall) {
	name := c.name
	if name == "" {
		name = firstNonEmpty(c.typ, "function_call")
		if name == "local_shell_call" {
			name = "local_shell"
		}
	}
	texts := c.texts()
	if len(texts) == 0 {
		texts = []string{"{}"}
	}
	for _, a := range texts {
		tc := sseToolCall{ID: c.id, Type: "function"}
		tc.Function.Name, tc.Function.Arguments = name, a
		s.AddCalls([]sseToolCall{tc})
	}
}

// finishOpen judges every open Responses item with what its deltas and its
// .done event carried, and closes it, in the order the items opened: the
// response ended (or the stream did) without the item's output_item.done
// (GAP-0321). keep keeps their text, so a part that comes later is judged
// with it. The late text of judged items is judged too.
func (s *sseToolCalls) finishOpen(keep bool) {
	items := slices.SortedFunc(maps.Values(s.open), func(a, b *sseRespCall) int { return a.seq - b.seq })
	for _, c := range items {
		s.judgeResp(c)
		s.closeResp(c, keep)
	}
	for _, c := range s.late {
		s.judgeResp(c)
		c.late = false
	}
	s.late = nil
}

// growResp counts n bytes of Responses item text; false: past the bound,
// the text is not kept (the stream is Broken).
func (s *sseToolCalls) growResp(n int) bool {
	s.respHeld += n
	if s.held+s.respHeld > sseToolCallMax {
		s.broken = true
	}
	return !s.broken
}

// blockCall is the call of a finished Anthropic tool_use block.
func blockCall(c *sseChatCall) sseToolCall {
	tc := sseToolCall{ID: c.id, Type: "function"}
	tc.Function.Name, tc.Function.Arguments = c.name, c.args.String()
	if tc.Function.Arguments == "" {
		tc.Function.Arguments = "{}"
	}
	return tc
}

// settle lets the Chat Completions and Anthropic call text go when no such
// call is open.
func (s *sseToolCalls) settle() {
	if len(s.chatOrder) == 0 && len(s.blocks) == 0 {
		s.held = 0
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
	root, err := parseJSONTree([]byte(data), s.maxValues)
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
	idx := -1
	if hasOutIdx {
		idx = outIdx
	}
	// itemKey is the key of the item an event names. An item id names that
	// item only: an added event with a new id is a new item, whatever its
	// output_index. A .delta or .done event with an id may name the open item
	// that its added event left without one, at its output_index. An event
	// without an id finds the open item of its output_index, else the last
	// one closed there.
	itemKey := func(id string, added bool) string {
		if id != "" {
			if s.open[id] == nil && s.closed[id] == nil && !added && hasOutIdx {
				if k, ok := s.byIdx[outIdx]; ok && strings.HasPrefix(k, sseRespIdxKey) {
					s.rekey(s.open[k], id)
				}
			}
			return id
		}
		if hasOutIdx {
			if k, ok := s.byIdx[outIdx]; ok {
				return k
			}
			if k, ok := s.closedIdx[outIdx]; ok && !added {
				return k
			}
		}
		return sseRespIdxKey + strconv.Itoa(outIdx)
	}
	switch {
	case typ == "response.output_item.added" || typ == "response.output_item.done":
		item := root.get("item")
		if item == nil || item.kind != 'o' || !isCallType(item.str("type")) {
			break
		}
		added := typ == "response.output_item.added"
		key := itemKey(item.str("id"), added)
		if added {
			if c := s.closed[key]; c != nil {
				// An item added again opens anew (its late text is judged).
				s.dropClosed(c)
			}
			if !serverCallType(item.str("type")) {
				c := s.respItem(key, idx)
				fn := item.get("function")
				c.id = firstNonEmpty(item.str("call_id"), item.str("id"))
				c.name = firstNonEmpty(item.str("name"), fn.str("name"), item.str("tool_name"), item.str("toolName"))
				c.typ = item.str("type")
			}
			break
		}
		w := &textWalker{reply: true}
		w.callObject(item, "")
		for _, c := range w.calls {
			s.finished(c)
		}
		if open := s.open[key]; open != nil {
			if open.name == "" && len(w.calls) > 0 {
				// The item's own call is the last the walker records (the
				// calls nested in its fields come first).
				open.name = w.calls[len(w.calls)-1].Function.Name
			}
			if len(open.texts()) > 0 {
				// A delta text the finished item does not carry is judged too.
				s.judgeResp(open)
			}
			s.closeResp(open, false)
		}
	case strings.HasPrefix(typ, "response.") && strings.Contains(typ, "_call") &&
		(strings.HasSuffix(typ, ".delta") || strings.HasSuffix(typ, ".done")):
		// function_call_arguments, custom_tool_call_input, mcp_call_arguments,
		// code_interpreter_call_code ...: the item is open even if its
		// output_item.added was not seen. A .done event carries the item's
		// whole text (arguments, input), and some providers end the item there.
		ct := callTypeOfEvent(typ)
		if serverCallType(ct) {
			break
		}
		c := s.respItem(itemKey(root.str("item_id"), false), idx)
		if c.typ == "" {
			c.typ = ct
		}
		if strings.HasSuffix(typ, ".delta") {
			if d := root.get("delta"); d != nil && d.kind == 's' && s.growResp(len(d.s)) {
				c.args.WriteString(d.s)
			}
			break
		}
		if c.name == "" {
			c.name = root.str("name")
		}
		for _, f := range []string{"arguments", "input", "code"} {
			v := root.get(f)
			if v == nil || v.kind != 's' {
				continue
			}
			switch {
			case c.args.Len() == 0:
				if s.growResp(len(v.s)) {
					c.args.WriteString(v.s)
				}
			case v.s != c.args.String() && v.s != c.doneText:
				// Kept beside the deltas, and counted like them.
				s.respHeld -= len(c.doneText)
				c.doneText = ""
				if s.growResp(len(v.s)) {
					c.doneText = v.s
				}
			}
			break
		}
		if c.late {
			// The whole text of a judged item: judged now, nothing is held
			// for it.
			s.judgeResp(c)
			s.unlate(c)
		}
	case typ == "response.completed" || typ == "response.failed" || typ == "response.incomplete":
		// The response is over: an item still open is judged with what its
		// deltas carried (the snapshot's own calls follow through AddCalls).
		// Its text is kept: a part that still comes is judged with it.
		s.finishOpen(true)
	case typ == "content_block_start":
		idx, _ := jnodeInt(root.get("index"))
		if cb := root.get("content_block"); cb != nil && isCallType(cb.str("type")) {
			c := &sseChatCall{id: cb.str("id"), name: cb.str("name")}
			if in := cb.get("input"); in != nil && in.kind == 'o' && len(in.kids) > 0 {
				c.args.WriteString(in.json())
			}
			if serverCallType(cb.str("type")) {
				s.serverBlocks[idx] = c
			} else {
				s.blocks[idx] = c
			}
		}
	case typ == "content_block_delta":
		idx, _ := jnodeInt(root.get("index"))
		if d := root.get("delta"); d != nil && d.str("type") == "input_json_delta" {
			if c := s.serverBlocks[idx]; c != nil {
				c.args.WriteString(d.str("partial_json"))
				break
			}
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
		if c := s.serverBlocks[idx]; c != nil {
			delete(s.serverBlocks, idx)
			s.finished(blockCall(c))
		}
		if c := s.blocks[idx]; c != nil {
			delete(s.blocks, idx)
			s.finished(blockCall(c))
			s.settle()
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
	if s.held+s.respHeld > sseToolCallMax {
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
	s.settle()
}

// Finish ends the stream: Chat Completions calls with no finish_reason are
// finished; an open Responses item or content block can no longer be
// completed, so the stream is Broken, and the item or block is judged with
// what it carried.
func (s *sseToolCalls) Finish() {
	s.finishChat()
	if len(s.open) > 0 || len(s.late) > 0 || len(s.blocks) > 0 {
		// Cut inside a call (or inside late deltas of a judged one): the
		// fail mode applies (Broken), and what the call carried so far still
		// goes through the tool-call rules (GAP-0321).
		s.broken = true
	}
	s.finishOpen(false)
	for _, idx := range slices.Sorted(maps.Keys(s.blocks)) {
		s.AddCalls([]sseToolCall{blockCall(s.blocks[idx])})
	}
	s.blocks = map[int]*sseChatCall{}
}

// Open reports a tool call in progress, or late text of a judged one not yet
// judged, whose bytes are held.
func (s *sseToolCalls) Open() bool {
	return len(s.open) > 0 || len(s.late) > 0 || len(s.chatOrder) > 0 || len(s.blocks) > 0
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
