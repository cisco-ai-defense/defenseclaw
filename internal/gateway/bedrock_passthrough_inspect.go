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
	model  string
}

func newBedrockEventStreamText() *bedrockEventStreamText {
	return &bedrockEventStreamText{dec: eventstream.NewDecoder()}
}

// Broken reports a stream the decoder could not frame.
func (s *bedrockEventStreamText) Broken() bool { return s.broken }

// Pending is the bytes of the message not yet complete: their text is not
// read yet.
func (s *bedrockEventStreamText) Pending() int { return len(s.buf) }

// Model is the model the stream named (Anthropic message_start), if any.
func (s *bedrockEventStreamText) Model() string { return s.model }

// Feed takes the next bytes of the stream and returns the text of the
// messages they complete.
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
	switch etype {
	case "chunk":
		// InvokeModelWithResponseStream: {"bytes":"<base64 model event>"};
		// for Claude the event is an Anthropic stream event.
		var c struct {
			Bytes string `json:"bytes"`
		}
		if json.Unmarshal(msg.Payload, &c) != nil || c.Bytes == "" {
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
		return bedrockInvokeChunkPieces(inner)
	case "contentBlockDelta":
		// ConverseStream: the event type names the frame, the payload is
		// {"contentBlockIndex":0,"delta":{"text" | "reasoningContent":{"text"}
		// | "toolUse":{"input"}}}.
		var d bedrockStreamDelta
		if json.Unmarshal(msg.Payload, &d) == nil {
			return d.pieces()
		}
	}
	return nil
}
