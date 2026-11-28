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
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"
)

// Bedrock's native model API (GAP-0098). InvokeModel answers in the shape
// of the model family (an Anthropic Messages body for Claude), and
// InvokeModelWithResponseStream and ConverseStream answer in the binary
// AWS eventstream. The passthrough proxy inspects both: the body by its
// family, the stream frame by frame while the bytes go to the caller
// unchanged.

// bedrockStreamingPath reports a Bedrock path that answers with a stream.
func bedrockStreamingPath(p string) bool {
	return strings.HasSuffix(p, "/invoke-with-response-stream") || strings.HasSuffix(p, "/converse-stream")
}

// bedrockInvokeText is the assistant text of an InvokeModel body: the
// Anthropic Messages shape (Claude), the Llama, Mistral, Cohere and Titan
// shapes, or the OpenAI-compatible chat shape (gpt-oss, Mistral Large,
// Jamba, DeepSeek: every choice, GAP-0519). "" when the body has none.
// Nova answers in the Converse shape, which the caller reads first.
func bedrockInvokeText(body []byte) string {
	if t := extractPassthroughResponseContent(body, "anthropic"); t != "" {
		return t
	}
	var other struct {
		Generation string `json:"generation"` // Meta Llama
		Outputs    []struct {
			Text string `json:"text"`
		} `json:"outputs"` // Mistral
		Generations []struct {
			Text string `json:"text"`
		} `json:"generations"` // Cohere Command
		Completion string          `json:"completion"` // Anthropic text completions
		Text       json.RawMessage `json:"text"`       // Cohere Command R
		Results    []struct {
			OutputText string `json:"outputText"`
		} `json:"results"` // Titan Text
		Choices []chatShapeChoice `json:"choices"` // chat shape
	}
	if json.Unmarshal(body, &other) != nil {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(other.Generation)
	sb.WriteString(other.Completion)
	for _, o := range other.Outputs {
		sb.WriteString(o.Text)
	}
	for _, g := range other.Generations {
		sb.WriteString(g.Text)
	}
	sb.WriteString(respJSONString(other.Text))
	for _, r := range other.Results {
		sb.WriteString(r.OutputText)
	}
	if sb.Len() > 0 {
		return sb.String()
	}
	return responsePiecesText(chatChoicesPieces(other.Choices, false))
}

// bedrockInvokeToolCalls is the tool calls of an InvokeModel body that is
// not Converse shaped: Anthropic tool_use blocks (Claude), the chat shape's
// tool_calls and legacy function_call (GAP-0519), and Cohere Command R
// tool_calls (name and parameters).
func bedrockInvokeToolCalls(body []byte) json.RawMessage {
	if raw := extractPassthroughToolCalls(body, "anthropic"); raw != nil {
		return raw
	}
	if raw := extractPassthroughToolCalls(body, "openai"); raw != nil {
		return raw
	}
	var cohere struct {
		ToolCalls []struct {
			Name       string          `json:"name"`
			Parameters json.RawMessage `json:"parameters"`
		} `json:"tool_calls"`
	}
	if json.Unmarshal(body, &cohere) != nil || len(cohere.ToolCalls) == 0 {
		return nil
	}
	type fn struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	}
	type call struct {
		Type     string `json:"type"`
		Function fn     `json:"function"`
	}
	calls := make([]call, 0, len(cohere.ToolCalls))
	for _, tc := range cohere.ToolCalls {
		if tc.Name != "" {
			calls = append(calls, call{Type: "function", Function: fn{Name: tc.Name, Arguments: jsonArgsText(tc.Parameters)}})
		}
	}
	if len(calls) == 0 {
		return nil
	}
	b, err := json.Marshal(calls)
	if err != nil {
		return nil
	}
	return b
}

// bedrockInvokeChunkPieces reads one InvokeModelWithResponseStream chunk
// by the shape of the model family: Anthropic stream events (Claude), the
// Nova contentBlockDelta (text, reasoning, tool input), the chat shape
// (every choice, tool input included), Mistral outputs, and the
// generation, outputText, completion and text fields (Llama, Titan,
// Anthropic text completions, Cohere), GAP-0519.
func bedrockInvokeChunkPieces(inner []byte) []responsePiece {
	if pieces := anthropicStreamPieces(inner); len(pieces) > 0 {
		return pieces
	}
	var ev struct {
		Generation        string              `json:"generation"`
		OutputText        string              `json:"outputText"`
		Completion        string              `json:"completion"`
		Text              json.RawMessage     `json:"text"`
		ContentBlockDelta *bedrockStreamDelta `json:"contentBlockDelta"`
		Choices           []chatShapeChoice   `json:"choices"`
		Outputs           []struct {
			Text string `json:"text"`
		} `json:"outputs"`
		ToolCalls []struct {
			Parameters json.RawMessage `json:"parameters"`
		} `json:"tool_calls"` // Cohere Command R tool-calls-generation
	}
	if json.Unmarshal(inner, &ev) != nil {
		return nil
	}
	out := []responsePiece{answerPiece(0, ev.Generation+ev.OutputText+ev.Completion+respJSONString(ev.Text))}
	if ev.ContentBlockDelta != nil {
		out = append(out, ev.ContentBlockDelta.pieces()...)
	}
	out = append(out, chatChoicesPieces(ev.Choices, true)...)
	for i, o := range ev.Outputs {
		out = append(out, answerPiece(i, o.Text))
	}
	for i, tc := range ev.ToolCalls {
		out = append(out, toolInputPiece(0, i, jsonArgsText(tc.Parameters)))
	}
	return out
}

// bedrockStreamMaxFrame bounds one eventstream message the inspector holds.
const bedrockStreamMaxFrame = 16 << 20

// bedrockEventStreamText decodes an AWS eventstream as it arrives and
// returns the model text of each whole message (answer, reasoning and tool
// input, GAP-0370). It keeps only the
// bytes of the message not yet complete. A malformed stream stops the
// decoding (the bytes still reach the caller); Broken reports it.
type bedrockEventStreamText struct {
	buf    []byte
	dec    *eventstream.Decoder
	broken bool
	// cut: the stream ended inside a tool call the agent runs (Finish).
	cut   bool
	model string
	// Tool calls (GAP-0098): open blocks by content index, assembled from
	// the stream's input deltas, and the finished calls not yet taken.
	tools    map[int]*bedrockStreamTool
	done     []bedrockStreamTool
	converse bool // a ConverseStream (else InvokeModelWithResponseStream)
	maxIndex int  // the highest content index read so far, -1 none
	// ambiguous is why an event can be read two ways (a repeated or
	// differently spelled key), "" when none: the stream takes the fail mode.
	ambiguous string
	// maxValues is the value cap of an event (guardrail.max_body_values).
	maxValues int
}

// bedrockStreamTool is one tool call of a stream.
type bedrockStreamTool struct {
	Name string
	Args strings.Builder
	// Server is a call the provider runs itself (server_tool_use,
	// mcp_tool_use): it is read by the tool-call rules when it ends and the
	// stream is not held for it (GAP-0249).
	Server bool
}

// bedrockStreamToolMax bounds one tool call's assembled input; a larger one
// cannot be inspected and makes the stream uninspectable.
const bedrockStreamToolMax = 1 << 20

// Holding reports a tool call that is still open or not yet inspected: its
// bytes must not reach the agent before the tool-call rules decide.
func (s *bedrockEventStreamText) Holding() bool {
	for _, t := range s.tools {
		if !t.Server {
			return true
		}
	}
	for i := range s.done {
		if !s.done[i].Server {
			return true
		}
	}
	return false
}

// TakeToolCalls returns the finished tool calls in the shape
// inspectToolCalls reads (nil for none) and forgets them.
func (s *bedrockEventStreamText) TakeToolCalls() json.RawMessage {
	if len(s.done) == 0 {
		return nil
	}
	type fn struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	}
	type call struct {
		Type     string `json:"type"`
		Function fn     `json:"function"`
	}
	out := make([]call, 0, len(s.done))
	for i := range s.done {
		args := strings.TrimSpace(s.done[i].Args.String())
		if args == "" {
			args = "{}"
		}
		out = append(out, call{Type: "function", Function: fn{Name: s.done[i].Name, Arguments: args}})
	}
	s.done = nil
	raw, _ := json.Marshal(out)
	return raw
}

func (s *bedrockEventStreamText) toolStart(index int, name, initial string, server bool) {
	if index > s.maxIndex {
		s.maxIndex = index
	}
	if name == "" {
		return
	}
	if s.tools == nil {
		s.tools = map[int]*bedrockStreamTool{}
	}
	t := &bedrockStreamTool{Name: name, Server: server}
	if initial = strings.TrimSpace(initial); initial != "" && initial != "{}" {
		t.Args.WriteString(initial)
	}
	s.tools[index] = t
}

func (s *bedrockEventStreamText) toolDelta(index int, part string) {
	t, ok := s.tools[index]
	if !ok {
		return
	}
	if t.Args.Len()+len(part) > bedrockStreamToolMax {
		s.broken, s.buf = true, nil
		return
	}
	t.Args.WriteString(part)
}

func (s *bedrockEventStreamText) toolStop(index int) {
	if t, ok := s.tools[index]; ok {
		s.done = append(s.done, bedrockStreamTool{Name: t.Name, Server: t.Server})
		s.done[len(s.done)-1].Args.WriteString(t.Args.String())
		delete(s.tools, index)
	}
}

// anthropicStreamToolEvent reads the tool-call parts of one Anthropic
// stream event.
func (s *bedrockEventStreamText) anthropicStreamToolEvent(inner []byte) {
	var ev struct {
		Type         string `json:"type"`
		Index        int    `json:"index"`
		ContentBlock struct {
			Type  string          `json:"type"`
			Name  string          `json:"name"`
			Input json.RawMessage `json:"input"`
		} `json:"content_block"`
		Delta struct {
			Type        string `json:"type"`
			PartialJSON string `json:"partial_json"`
		} `json:"delta"`
	}
	if json.Unmarshal(inner, &ev) != nil {
		return
	}
	switch ev.Type {
	case "content_block_start", "content_block_delta", "content_block_stop":
		// Every content block event names its block, also a block whose
		// content_block_start the stream left out (GAP-1206).
		if ev.Index > s.maxIndex {
			s.maxIndex = ev.Index
		}
	}
	switch ev.Type {
	case "content_block_start":
		if ev.ContentBlock.Type == "tool_use" || serverCallType(ev.ContentBlock.Type) {
			s.toolStart(ev.Index, ev.ContentBlock.Name, string(ev.ContentBlock.Input), serverCallType(ev.ContentBlock.Type))
		}
	case "content_block_delta":
		if ev.Delta.Type == "input_json_delta" {
			s.toolDelta(ev.Index, ev.Delta.PartialJSON)
		}
	case "content_block_stop":
		s.toolStop(ev.Index)
	}
}

func newBedrockEventStreamText() *bedrockEventStreamText {
	return &bedrockEventStreamText{dec: eventstream.NewDecoder(), maxIndex: -1}
}

// Broken reports a stream the decoder could not frame.
func (s *bedrockEventStreamText) Broken() bool { return s.broken }

// Ambiguous is why a frame of the stream can be read two ways, if one can.
func (s *bedrockEventStreamText) Ambiguous() string { return s.ambiguous }

// Model is the model the stream named (Anthropic message_start), if any.
func (s *bedrockEventStreamText) Model() string { return s.model }

// PartialLen is how many bytes at the end of what Feed took belong to a
// frame that is not complete yet; a forwarder holds them back so the
// receiver only ever gets whole frames.
func (s *bedrockEventStreamText) PartialLen() int { return len(s.buf) }

// Finish ends the tool calls still open when the stream ended (a stream cut
// inside a call): they are handed to the tool-call rules like finished ones,
// and a cut call the agent runs (not a server call) marks the stream Cut, so
// the tier's fail mode applies after the rules (GAP-0987).
// A stream the decoder could not frame has no reliable open calls.
func (s *bedrockEventStreamText) Finish() {
	if s.broken {
		return
	}
	idx := make([]int, 0, len(s.tools))
	for i := range s.tools {
		idx = append(idx, i)
	}
	sort.Ints(idx)
	for _, i := range idx {
		if !s.tools[i].Server {
			s.cut = true
		}
		s.toolStop(i)
	}
}

// Cut reports a stream that ended inside a tool call the agent runs.
func (s *bedrockEventStreamText) Cut() bool { return s.cut }

// Feed takes the next bytes of the stream and returns the model text of
// the messages they complete (messagePieces).
func (s *bedrockEventStreamText) Feed(p []byte) []responsePiece {
	if s.broken {
		return nil
	}
	s.buf = append(s.buf, p...)
	var out []responsePiece
	for len(s.buf) >= 12 {
		total := int(binary.BigEndian.Uint32(s.buf[:4]))
		if total < 16 || total > bedrockStreamMaxFrame {
			s.broken, s.buf = true, nil
			break
		}
		if len(s.buf) < total {
			break
		}
		msg, err := s.dec.Decode(bytes.NewReader(s.buf[:total]), nil)
		s.buf = s.buf[total:]
		if err != nil {
			s.broken, s.buf = true, nil
			break
		}
		out = append(out, s.messagePieces(msg)...)
	}
	if len(s.buf) == 0 {
		s.buf = nil
	}
	return out
}

// eventSegments reads one event payload (a Converse event, or the decoded
// Anthropic or model-native chunk) with the walker every other reply format
// goes through: every string of the event is inspected, except the fields
// known not to be text (GAP-0239). The tool calls of the event are the
// business of the stream state machine, not of this text.
func (s *bedrockEventStreamText) eventSegments(payload []byte) []string {
	sc, err := scanReplyJSON(payload, true, s.maxValues)
	if err != nil {
		// Not JSON: the text itself is the content, as for an SSE event.
		if utf8.Valid(payload) {
			return []string{string(payload)}
		}
		return nil
	}
	if sc.Ambiguous != "" && s.ambiguous == "" {
		s.ambiguous = sc.Ambiguous
	}
	return sc.Segments
}

// messagePieces is the model text of one message: the typed fields of the
// model family, each in its lane (GAP-0370, GAP-0519), and every other
// string of the event the walker reads (withWalkerPieces). It also feeds
// the tool-call state machine.
func (s *bedrockEventStreamText) messagePieces(msg eventstream.Message) []responsePiece {
	var mtype, etype string
	for _, h := range msg.Headers {
		switch h.Name {
		case ":message-type":
			mtype = h.Value.String()
		case ":event-type":
			etype = h.Value.String()
		}
	}
	if mtype != "event" {
		return nil
	}
	var typed []responsePiece
	switch etype {
	case "chunk":
		// InvokeModelWithResponseStream: {"bytes":"<base64 model event>"};
		// for Claude the event is an Anthropic stream event.
		var c struct {
			Bytes string `json:"bytes"`
		}
		if json.Unmarshal(msg.Payload, &c) != nil {
			return withWalkerPieces(nil, s.eventSegments(msg.Payload))
		}
		if c.Bytes == "" {
			return nil
		}
		inner, err := base64.StdEncoding.DecodeString(c.Bytes)
		if err != nil {
			return nil
		}
		if s.model == "" {
			var start struct {
				Message struct {
					Model string `json:"model"`
				} `json:"message"`
			}
			if json.Unmarshal(inner, &start) == nil {
				s.model = start.Message.Model
			}
		}
		s.anthropicStreamToolEvent(inner)
		return withWalkerPieces(bedrockInvokeChunkPieces(inner), s.eventSegments(inner))
	case "contentBlockStart":
		// ConverseStream tool call: {"contentBlockIndex":n,"start":
		// {"toolUse":{"toolUseId","name"}}}.
		s.converse = true
		var st struct {
			Index int `json:"contentBlockIndex"`
			Start struct {
				ToolUse struct {
					Name string `json:"name"`
				} `json:"toolUse"`
			} `json:"start"`
		}
		if json.Unmarshal(msg.Payload, &st) == nil {
			s.toolStart(st.Index, st.Start.ToolUse.Name, "", false)
		}
	case "contentBlockDelta":
		// ConverseStream: the event type names the frame, the payload is
		// {"contentBlockIndex":0,"delta":{"text" | "reasoningContent":{"text"}
		// | "toolUse":{"input"}}}.
		s.converse = true
		var d bedrockStreamDelta
		if json.Unmarshal(msg.Payload, &d) == nil {
			if d.ContentBlockIndex > s.maxIndex {
				s.maxIndex = d.ContentBlockIndex
			}
			if d.Delta.ToolUse.Input != "" {
				s.toolDelta(d.ContentBlockIndex, d.Delta.ToolUse.Input)
			}
			typed = d.pieces()
		}
	case "contentBlockStop":
		s.converse = true
		var st struct {
			Index int `json:"contentBlockIndex"`
		}
		if json.Unmarshal(msg.Payload, &st) == nil {
			s.toolStop(st.Index)
		}
		typed = []responsePiece{laneEndPiece(0)} // GAP-2154, GAP-2162: parked
	case "messageStop":
		typed = []responsePiece{messageEndPiece(0)}
	}
	// Every event goes through the walker, whatever its type.
	return withWalkerPieces(typed, s.eventSegments(msg.Payload))
}

// headersSentWriter is w after the reply headers went out: header writes
// and a second WriteHeader are dropped, body writes and flushes pass, so a
// block writer can add its frames to a stream already open.
type headersSentWriter struct {
	http.ResponseWriter
	h http.Header
}

func (w *headersSentWriter) Header() http.Header {
	if w.h == nil {
		w.h = http.Header{}
	}
	return w.h
}
func (w *headersSentWriter) WriteHeader(int) {}
func (w *headersSentWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// writeBlockTail ends a Bedrock stream the agent already received part of
// with the block message as one more text block of the same message, at
// idx, the index after the last content block the agent got (the message
// then ends normally), so the agent shows it instead of a cut stream.
func (s *bedrockEventStreamText) writeBlockTail(w io.Writer, idx int, msg string) {
	if s.converse {
		for _, f := range []struct {
			t string
			p map[string]any
		}{
			{"contentBlockDelta", map[string]any{"contentBlockIndex": idx, "delta": map[string]any{"text": msg}, "p": ""}},
			{"contentBlockStop", map[string]any{"contentBlockIndex": idx, "p": ""}},
			{"messageStop", map[string]any{"stopReason": bedrockBlockStopReason, "defenseclaw_blocked": true, "p": ""}},
		} {
			if writeBedrockEventStreamFrame(w, f.t, f.p) != nil {
				return
			}
		}
		return
	}
	for _, ev := range []map[string]any{
		{"type": "content_block_start", "index": idx, "content_block": map[string]any{"type": "text", "text": ""}},
		{"type": "content_block_delta", "index": idx, "delta": map[string]any{"type": "text_delta", "text": msg}},
		{"type": "content_block_stop", "index": idx},
		{"type": "message_delta", "delta": map[string]any{"stop_reason": bedrockBlockStopReason, "stop_sequence": nil}, "usage": map[string]int{"output_tokens": 1}},
		{"type": "message_stop"},
	} {
		raw, _ := json.Marshal(ev)
		if writeBedrockEventStreamFrame(w, "chunk", map[string]any{"bytes": base64.StdEncoding.EncodeToString(raw)}) != nil {
			return
		}
	}
}
