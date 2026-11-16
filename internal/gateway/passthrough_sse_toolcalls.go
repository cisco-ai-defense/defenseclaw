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
//     text that differs from the finished item. Identity (sseRespCall): an
//     event names the item of its id, or, with no id, the id-less item open
//     at its output_index; anything else is a new item. An item keeps every
//     name it is given and its text is judged under each. Text that comes
//     for an item after it was judged never reopens it: a whole .done text
//     is judged at once, a delta after output_item.done makes the stream
//     Broken;
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
	// Responses call items (sseRespCall). byID holds the items that have an
	// id, open or judged; idless the open item without one at each
	// output_index, and closedIdless the last judged one there. open is the
	// set of open items, late the judged ones whose late text is held.
	byID         map[string]*sseRespCall
	idless       map[int]*sseRespCall
	closedIdless map[int]*sseRespCall
	open         map[*sseRespCall]struct{}
	late         []*sseRespCall
	openSeq      int // the next item's place in the order items open
	closedN      int // judged items remembered (at most sseRespClosedMax)
	// respHeld counts all the Responses items keep: the text of open items,
	// text a response end kept, late text, and every remembered item's id,
	// call id, type and names. With held (the Chat Completions and
	// Anthropic call text) it is bounded by sseToolCallMax.
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

// sseRespCall is a Responses call item. Its identity is its id, or, for an
// item without one, its output_index while it is open: an event attaches to
// an item only when that identity agrees (resolveResp). Names are never
// overwritten: the item collects every non-empty name it is given (added,
// output_item.done, its .done events, an add again) and its text is judged
// under each.
type sseRespCall struct {
	id, callID string
	names      []string
	typ        string // the item type: function_call, custom_tool_call ...
	outIdx     int    // output_index, -1 when unknown
	seq        int    // the order the item opened in
	args       strings.Builder
	// doneText is the text of the item's *_call_*.done event when it
	// differs from the deltas (when there were none it is in args).
	doneText string
	closed   bool // judged
	// kept: judged by the end of a response, its text kept, so a delta that
	// still comes joins it (judged whole with it at the end).
	kept   bool
	lateAt int // the item's place in sseToolCalls.late, -1 when not there
}

// sseRespClosedMax bounds the judged items a stream remembers by count, as
// respHeld does by bytes. Past it they are forgotten (their late text judged
// first): an event of a forgotten item makes a new one.
const sseRespClosedMax = 1 << 14

// sseRespNamesMax bounds the names one item collects; more make the stream
// Broken.
const sseRespNamesMax = 8

// sseRespItemCost is what one remembered item counts besides its strings.
const sseRespItemCost = 64

func (c *sseRespCall) meta() int {
	n := sseRespItemCost + len(c.id) + len(c.callID) + len(c.typ)
	for _, nm := range c.names {
		n += len(nm)
	}
	return n
}

func (c *sseRespCall) text() int { return c.args.Len() + len(c.doneText) }

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

func newSSEToolCalls(maxValues int) *sseToolCalls {
	return &sseToolCalls{maxValues: maxValues, byID: map[string]*sseRespCall{}, idless: map[int]*sseRespCall{},
		closedIdless: map[int]*sseRespCall{}, open: map[*sseRespCall]struct{}{}, chat: map[int]*sseChatCall{},
		blocks: map[int]*sseChatCall{}, serverBlocks: map[int]*sseChatCall{}, seen: map[string]bool{}}
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

// setBroken marks the stream uninspectable (the fail mode). The judged
// Responses items are forgotten, and no new item is remembered.
func (s *sseToolCalls) setBroken() {
	if s.broken {
		return
	}
	s.broken = true
	s.forgetClosed()
}

// account counts n more bytes of Responses item memory; false when that is
// past the bound (the stream is Broken and the bytes are not kept).
func (s *sseToolCalls) account(n int) bool {
	s.respHeld += n
	if s.held+s.respHeld > sseToolCallMax {
		s.setBroken()
	}
	return !s.broken
}

// resolveResp is the Responses item an event names (nil when none and not
// create, or when the stream is Broken). An event with an id names the item
// of that id only. An event without one names the id-less item open at its
// output_index; a .delta or .done event (not an added one) also the id-less
// item judged last there. An item with an id is never reached by index.
func (s *sseToolCalls) resolveResp(id string, idx int, added, create bool) *sseRespCall {
	if id != "" {
		if c := s.byID[id]; c != nil {
			return c
		}
	} else {
		if c := s.idless[idx]; c != nil {
			return c
		}
		if c := s.closedIdless[idx]; c != nil && !added {
			return c
		}
	}
	if !create || s.broken {
		return nil
	}
	c := &sseRespCall{id: id, outIdx: idx, seq: s.openSeq, lateAt: -1}
	if !s.account(c.meta()) {
		return nil
	}
	s.openSeq++
	if id != "" {
		s.byID[id] = c
	} else {
		s.idless[idx] = c
	}
	s.open[c] = struct{}{}
	return c
}

// reopen opens a judged item that is added again (its kept text stays).
func (s *sseToolCalls) reopen(c *sseRespCall) {
	if c.lateAt >= 0 {
		s.unlate(c)
	}
	c.closed, c.kept = false, false
	s.closedN--
	s.open[c] = struct{}{}
}

// addName adds a name the item is given (once).
func (s *sseToolCalls) addName(c *sseRespCall, name string) {
	if name == "" || slices.Contains(c.names, name) {
		return
	}
	if len(c.names) >= sseRespNamesMax {
		s.setBroken()
		return
	}
	if s.account(len(name)) {
		c.names = append(c.names, name)
	}
}

// setMeta fills the item's call id and type when it has none.
func (s *sseToolCalls) setMeta(c *sseRespCall, callID, typ string) {
	if c.callID == "" && callID != "" && s.account(len(callID)) {
		c.callID = callID
	}
	if c.typ == "" && typ != "" && s.account(len(typ)) {
		c.typ = typ
	}
}

// markLate puts the judged item c on the late list (once).
func (s *sseToolCalls) markLate(c *sseRespCall) {
	if c.lateAt < 0 {
		c.lateAt = len(s.late)
		s.late = append(s.late, c)
	}
}

// unlate takes c off the late list (swap with the last).
func (s *sseToolCalls) unlate(c *sseRespCall) {
	i, last := c.lateAt, len(s.late)-1
	s.late[i] = s.late[last]
	s.late[i].lateAt = i
	s.late[last] = nil
	s.late = s.late[:last]
	c.lateAt = -1
}

// closeResp judges nothing; it moves the open item c to the judged ones.
// keep keeps its text (a delta that comes later is judged with it); else the
// text is let go.
func (s *sseToolCalls) closeResp(c *sseRespCall, keep bool) {
	delete(s.open, c)
	if c.id == "" {
		if s.idless[c.outIdx] == c {
			delete(s.idless, c.outIdx)
		}
		if old := s.closedIdless[c.outIdx]; old != nil && old != c {
			s.dropClosed(old)
		}
		s.closedIdless[c.outIdx] = c
	}
	c.closed, c.kept = true, keep
	if !keep {
		s.respHeld -= c.text()
		c.args.Reset()
		c.doneText = ""
	}
	s.closedN++
	if s.closedN > sseRespClosedMax {
		s.forgetClosed()
	}
}

// dropClosed forgets one judged item after its late text is judged.
func (s *sseToolCalls) dropClosed(c *sseRespCall) {
	if c.lateAt >= 0 {
		s.judgeResp(c)
		s.unlate(c)
	}
	s.respHeld -= c.meta() + c.text()
	s.closedN--
	if c.id != "" && s.byID[c.id] == c {
		delete(s.byID, c.id)
	}
	if c.id == "" && s.closedIdless[c.outIdx] == c {
		delete(s.closedIdless, c.outIdx)
	}
}

// forgetClosed forgets every judged item (their late text judged first).
func (s *sseToolCalls) forgetClosed() {
	for len(s.late) > 0 {
		c := s.late[len(s.late)-1]
		s.judgeResp(c)
		s.unlate(c)
	}
	for id, c := range s.byID {
		if c.closed {
			s.respHeld -= c.meta() + c.text()
			delete(s.byID, id)
		}
	}
	for _, c := range s.closedIdless {
		s.respHeld -= c.meta() + c.text()
	}
	s.closedIdless = map[int]*sseRespCall{}
	s.closedN = 0
}

// judgeTexts adds the texts as calls of each of the item's names (of its
// type when it has none, as textWalker.callObject names a call), once each.
func (s *sseToolCalls) judgeTexts(c *sseRespCall, texts []string) {
	names := c.names
	if len(names) == 0 {
		name := firstNonEmpty(c.typ, "function_call")
		if name == "local_shell_call" {
			name = "local_shell"
		}
		names = []string{name}
	}
	for _, name := range names {
		for _, a := range texts {
			tc := sseToolCall{ID: firstNonEmpty(c.callID, c.id), Type: "function"}
			tc.Function.Name, tc.Function.Arguments = name, a
			s.AddCalls([]sseToolCall{tc})
		}
	}
}

// judgeResp judges what the item c carried (no arguments: "{}").
func (s *sseToolCalls) judgeResp(c *sseRespCall) {
	texts := c.texts()
	if len(texts) == 0 {
		texts = []string{"{}"}
	}
	s.judgeTexts(c, texts)
}

// finishOpen judges every open Responses item with what its deltas and its
// .done event carried, and closes it, in the order the items opened: the
// response ended (or the stream did) without the item's output_item.done
// (GAP-0321). keep keeps their text, so a delta that comes later is judged
// with it. The late text of judged items is judged too.
func (s *sseToolCalls) finishOpen(keep bool) {
	items := slices.SortedFunc(maps.Keys(s.open), func(a, b *sseRespCall) int { return a.seq - b.seq })
	for _, c := range items {
		s.judgeResp(c)
		s.closeResp(c, keep)
	}
	for len(s.late) > 0 {
		c := s.late[len(s.late)-1]
		s.judgeResp(c)
		s.unlate(c)
	}
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
	switch {
	case typ == "response.output_item.added" || typ == "response.output_item.done":
		item := root.get("item")
		if item == nil || item.kind != 'o' || !isCallType(item.str("type")) {
			break
		}
		ityp := item.str("type")
		if typ == "response.output_item.added" {
			if serverCallType(ityp) {
				break
			}
			c := s.resolveResp(item.str("id"), idx, true, true)
			if c == nil {
				break
			}
			if c.closed {
				s.reopen(c)
			}
			fn := item.get("function")
			s.addName(c, firstNonEmpty(item.str("name"), fn.str("name"), item.str("tool_name"), item.str("toolName")))
			s.setMeta(c, item.str("call_id"), ityp)
			break
		}
		w := &textWalker{reply: true}
		w.callObject(item, "")
		for _, call := range w.calls {
			s.finished(call)
		}
		if serverCallType(ityp) {
			break
		}
		c := s.resolveResp(item.str("id"), idx, false, false)
		if c == nil || c.closed {
			break // a judged item done again: the call above is judged
		}
		if len(w.calls) > 0 {
			// The item's own call is the last the walker records (the
			// calls nested in its fields come first).
			s.addName(c, w.calls[len(w.calls)-1].Function.Name)
		}
		if len(c.texts()) > 0 {
			// A delta text the finished item does not carry is judged too,
			// under every name the item has.
			s.judgeResp(c)
		}
		s.closeResp(c, false)
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
		c := s.resolveResp(root.str("item_id"), idx, false, true)
		if c == nil {
			break
		}
		s.setMeta(c, "", ct)
		if strings.HasSuffix(typ, ".delta") {
			d := root.get("delta")
			if d == nil || d.kind != 's' {
				break
			}
			switch {
			case !c.closed:
				if s.account(len(d.s)) {
					c.args.WriteString(d.s)
				}
			case c.kept:
				// After a response end: joins the kept text, held and judged
				// whole at the end.
				if s.account(len(d.s)) {
					c.args.WriteString(d.s)
				}
				s.markLate(c)
			default:
				// After the item's output_item.done: no provider sends one,
				// and the call is out already. The fail mode applies; the
				// piece is judged too.
				s.setBroken()
				s.judgeTexts(c, []string{d.s})
			}
			break
		}
		s.addName(c, root.str("name"))
		var v *jnode
		for _, f := range []string{"arguments", "input", "code"} {
			if n := root.get(f); n != nil && n.kind == 's' {
				v = n
				break
			}
		}
		switch {
		case v == nil:
		case c.closed:
			// The whole text of a judged item: judged now, under every
			// name it has, and nothing is held for it.
			s.judgeTexts(c, []string{v.s})
		case c.args.Len() == 0:
			if s.account(len(v.s)) {
				c.args.WriteString(v.s)
			}
		case v.s != c.args.String() && v.s != c.doneText:
			// Kept beside the deltas, and counted like them.
			s.respHeld -= len(c.doneText)
			c.doneText = ""
			if s.account(len(v.s)) {
				c.doneText = v.s
			}
		}
	case typ == "response.completed" || typ == "response.failed" || typ == "response.incomplete":
		// The response is over: an item still open is judged with what its
		// deltas carried (the snapshot's own calls follow through AddCalls).
		// Its text is kept: a delta that still comes is judged with it.
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
		s.setBroken()
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
		s.setBroken()
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
