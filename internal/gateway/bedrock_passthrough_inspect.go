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
// Anthropic Messages shape (Claude) or the Nova, Llama, Mistral and Cohere
// shapes. "" when the body has none.
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
		} `json:"generations"` // Cohere
		Completion string `json:"completion"` // Anthropic text completions
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
	return sb.String()
}

// bedrockStreamMaxFrame bounds one eventstream message the inspector holds.
const bedrockStreamMaxFrame = 16 << 20

// bedrockEventStreamText decodes an AWS eventstream as it arrives and
// returns the assistant text of each whole message. It keeps only the
// bytes of the message not yet complete. A malformed stream stops the
// decoding (the bytes still reach the caller); Broken reports it.
type bedrockEventStreamText struct {
	buf    []byte
	dec    *eventstream.Decoder
	broken bool
	model  string
	// Tool calls (GAP-0098): open blocks by content index, assembled from
	// the stream's input deltas, and the finished calls not yet taken.
	tools    map[int]*bedrockStreamTool
	done     []bedrockStreamTool
	converse bool // a ConverseStream (else InvokeModelWithResponseStream)
	maxIndex int
}

// bedrockStreamTool is one tool call of a stream.
type bedrockStreamTool struct {
	Name string
	Args strings.Builder
}

// bedrockStreamToolMax bounds one tool call's assembled input; a larger one
// cannot be inspected and makes the stream uninspectable.
const bedrockStreamToolMax = 1 << 20

// Holding reports a tool call that is still open or not yet inspected: its
// bytes must not reach the agent before the tool-call rules decide.
func (s *bedrockEventStreamText) Holding() bool { return len(s.tools) > 0 || len(s.done) > 0 }

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

func (s *bedrockEventStreamText) toolStart(index int, name, initial string) {
	if index > s.maxIndex {
		s.maxIndex = index
	}
	if name == "" {
		return
	}
	if s.tools == nil {
		s.tools = map[int]*bedrockStreamTool{}
	}
	t := &bedrockStreamTool{Name: name}
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
		s.done = append(s.done, bedrockStreamTool{Name: t.Name})
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
	case "content_block_start":
		if ev.ContentBlock.Type == "tool_use" || ev.ContentBlock.Type == "server_tool_use" {
			s.toolStart(ev.Index, ev.ContentBlock.Name, string(ev.ContentBlock.Input))
		} else if ev.Index > s.maxIndex {
			s.maxIndex = ev.Index
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
	return &bedrockEventStreamText{dec: eventstream.NewDecoder()}
}

// Broken reports a stream the decoder could not frame.
func (s *bedrockEventStreamText) Broken() bool { return s.broken }

// Model is the model the stream named (Anthropic message_start), if any.
func (s *bedrockEventStreamText) Model() string { return s.model }

// PartialLen is how many bytes at the end of what Feed took belong to a
// frame that is not complete yet; a forwarder holds them back so the
// receiver only ever gets whole frames.
func (s *bedrockEventStreamText) PartialLen() int { return len(s.buf) }

// Finish ends the tool calls still open when the stream ended (a stream cut
// inside a call): they are handed to the tool-call rules like finished ones.
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
		s.toolStop(i)
	}
}

// Feed takes the next bytes of the stream and returns the text of the
// messages they complete.
func (s *bedrockEventStreamText) Feed(p []byte) string {
	if s.broken {
		return ""
	}
	s.buf = append(s.buf, p...)
	var sb strings.Builder
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
		sb.WriteString(s.messageText(msg))
	}
	if len(s.buf) == 0 {
		s.buf = nil
	}
	return sb.String()
}

func (s *bedrockEventStreamText) messageText(msg eventstream.Message) string {
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
		return ""
	}
	switch etype {
	case "chunk":
		// InvokeModelWithResponseStream: {"bytes":"<base64 model event>"};
		// for Claude the event is an Anthropic stream event.
		var c struct {
			Bytes string `json:"bytes"`
		}
		if json.Unmarshal(msg.Payload, &c) != nil || c.Bytes == "" {
			return ""
		}
		inner, err := base64.StdEncoding.DecodeString(c.Bytes)
		if err != nil {
			return ""
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
		if t := extractSSEChunkText(string(inner), "anthropic"); t != "" {
			return t
		}
		var other struct {
			Generation string `json:"generation"`
			OutputText string `json:"outputText"`
			Completion string `json:"completion"`
		}
		if json.Unmarshal(inner, &other) == nil {
			return other.Generation + other.OutputText + other.Completion
		}
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
			s.toolStart(st.Index, st.Start.ToolUse.Name, "")
		}
	case "contentBlockDelta":
		// ConverseStream: the event type names the frame, the payload is
		// {"contentBlockIndex":0,"delta":{"text":"..."}} or a toolUse
		// input part {"delta":{"toolUse":{"input":"..."}}}.
		s.converse = true
		var d struct {
			Index int `json:"contentBlockIndex"`
			Delta struct {
				Text    string `json:"text"`
				ToolUse struct {
					Input string `json:"input"`
				} `json:"toolUse"`
			} `json:"delta"`
		}
		if json.Unmarshal(msg.Payload, &d) == nil {
			if d.Index > s.maxIndex {
				s.maxIndex = d.Index
			}
			if d.Delta.ToolUse.Input != "" {
				s.toolDelta(d.Index, d.Delta.ToolUse.Input)
			}
			return d.Delta.Text
		}
	case "contentBlockStop":
		s.converse = true
		var st struct {
			Index int `json:"contentBlockIndex"`
		}
		if json.Unmarshal(msg.Payload, &st) == nil {
			s.toolStop(st.Index)
		}
	}
	return ""
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
// with the block message as one more text block of the same message (the
// message then ends normally), so the agent shows it instead of a cut
// stream.
func (s *bedrockEventStreamText) writeBlockTail(w io.Writer, msg string) {
	idx := s.maxIndex + 1
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
