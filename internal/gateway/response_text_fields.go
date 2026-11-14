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
	"strings"
)

// The model text of a response, read per provider (GAP-0370). A client
// receives more model text than the answer: thinking or reasoning, a
// refusal, streamed tool input, and every choice or candidate. The
// completion checks read all of it. Each run of text (one field of one
// choice) is its own lane, and lanes are checked side by side, one per
// line, so the text of two choices or two fields never runs together into
// one match. A response with one lane is checked byte for byte as before.

type responseField uint8

const (
	responseFieldAnswer responseField = iota
	responseFieldReasoning
	responseFieldRefusal
	responseFieldToolInput
)

// responseLane names one run of model text: a choice (or candidate), a
// field of it, and for tool input the call within the choice.
type responseLane struct {
	choice int
	field  responseField
	part   int
}

type responsePiece struct {
	lane responseLane
	text string
}

func answerPiece(choice int, text string) responsePiece {
	return responsePiece{lane: responseLane{choice: choice, field: responseFieldAnswer}, text: text}
}

func reasoningPiece(choice int, text string) responsePiece {
	return responsePiece{lane: responseLane{choice: choice, field: responseFieldReasoning}, text: text}
}

func refusalPiece(choice int, text string) responsePiece {
	return responsePiece{lane: responseLane{choice: choice, field: responseFieldRefusal}, text: text}
}

func toolInputPiece(choice, call int, text string) responsePiece {
	return responsePiece{lane: responseLane{choice: choice, field: responseFieldToolInput, part: call}, text: text}
}

// responseText accumulates the model text of a response by lane, in the
// order the lanes first appear.
type responseText struct {
	lanes  []*strings.Builder
	index  map[responseLane]int
	n      int
	joined string
	fresh  bool
}

func (r *responseText) Add(p responsePiece) {
	if p.text == "" {
		return
	}
	i, ok := r.index[p.lane]
	if !ok {
		if r.index == nil {
			r.index = make(map[responseLane]int)
		}
		i = len(r.lanes)
		r.index[p.lane] = i
		r.lanes = append(r.lanes, &strings.Builder{})
	}
	r.lanes[i].WriteString(p.text)
	r.n += len(p.text)
	r.fresh = false
}

func (r *responseText) AddAll(ps []responsePiece) {
	for _, p := range ps {
		r.Add(p)
	}
}

// Len is the number of model text bytes, separators not counted.
func (r *responseText) Len() int { return r.n }

// String is the text the checks read: the lanes one per line.
func (r *responseText) String() string {
	switch len(r.lanes) {
	case 0:
		return ""
	case 1:
		return r.lanes[0].String()
	}
	if !r.fresh {
		var sb strings.Builder
		sb.Grow(r.n + len(r.lanes))
		for i, l := range r.lanes {
			if i > 0 {
				sb.WriteByte('\n')
			}
			sb.WriteString(l.String())
		}
		r.joined, r.fresh = sb.String(), true
	}
	return r.joined
}

func responsePiecesText(ps []responsePiece) string {
	var r responseText
	r.AddAll(ps)
	return r.String()
}

// respJSONString is the value of raw when it is a JSON string, else "". A field
// some providers send as an object (reasoning) then never fails the decode
// of the whole event.
func respJSONString(raw json.RawMessage) string {
	if len(raw) == 0 || raw[0] != '"' {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

// jsonArgsText is tool input as the client reads it: a JSON string's value,
// or an object's JSON text.
func jsonArgsText(raw json.RawMessage) string {
	if s := respJSONString(raw); s != "" {
		return s
	}
	switch t := strings.TrimSpace(string(raw)); t {
	case "", "null", "{}", "[]", `""`:
		return ""
	default:
		return t
	}
}

// chatShapeMessage is an OpenAI chat-shaped message or delta: content (a
// string or content parts), refusal, the reasoning fields OpenAI-compatible
// servers add (reasoning_content: DeepSeek, vLLM, xAI; reasoning:
// OpenRouter, Ollama), and tool calls.
type chatShapeMessage struct {
	Content          json.RawMessage `json:"content"`
	Refusal          json.RawMessage `json:"refusal"`
	ReasoningContent json.RawMessage `json:"reasoning_content"`
	Reasoning        json.RawMessage `json:"reasoning"`
	ToolCalls        []struct {
		Index    int `json:"index"`
		Function struct {
			Arguments json.RawMessage `json:"arguments"`
		} `json:"function"`
	} `json:"tool_calls"`
}

type chatShapeChoice struct {
	Index   int               `json:"index"`
	Delta   *chatShapeMessage `json:"delta"`
	Message *chatShapeMessage `json:"message"`
	Text    json.RawMessage   `json:"text"` // legacy completions
}

// chatContentPieces reads message content: a string, or parts of type
// text, output_text or refusal.
func chatContentPieces(choice int, raw json.RawMessage) []responsePiece {
	if s := respJSONString(raw); s != "" {
		return []responsePiece{answerPiece(choice, s)}
	}
	if len(raw) == 0 || raw[0] != '[' {
		return nil
	}
	var parts []struct {
		Type    string `json:"type"`
		Text    string `json:"text"`
		Refusal string `json:"refusal"`
	}
	if json.Unmarshal(raw, &parts) != nil {
		return nil
	}
	var out []responsePiece
	for _, p := range parts {
		switch p.Type {
		case "refusal":
			out = append(out, refusalPiece(choice, p.Refusal))
		case "text", "output_text", "":
			out = append(out, answerPiece(choice, p.Text))
		}
	}
	return out
}

// chatMessagePieces reads one chat-shaped message or delta. withTools adds
// tool-call arguments: the paths that do not inspect tool calls on their
// own read them as model text.
func chatMessagePieces(choice int, m *chatShapeMessage, withTools bool) []responsePiece {
	if m == nil {
		return nil
	}
	out := chatContentPieces(choice, m.Content)
	if s := respJSONString(m.Refusal); s != "" {
		out = append(out, refusalPiece(choice, s))
	}
	if s := respJSONString(m.ReasoningContent); s != "" {
		out = append(out, reasoningPiece(choice, s))
	}
	if s := respJSONString(m.Reasoning); s != "" {
		out = append(out, reasoningPiece(choice, s))
	}
	if withTools {
		for _, tc := range m.ToolCalls {
			out = append(out, toolInputPiece(choice, tc.Index, jsonArgsText(tc.Function.Arguments)))
		}
	}
	return out
}

func chatChoicesPieces(choices []chatShapeChoice, withTools bool) []responsePiece {
	var out []responsePiece
	for _, c := range choices {
		out = append(out, chatMessagePieces(c.Index, c.Delta, withTools)...)
		out = append(out, chatMessagePieces(c.Index, c.Message, withTools)...)
		if s := respJSONString(c.Text); s != "" {
			out = append(out, answerPiece(c.Index, s))
		}
	}
	return out
}

// llmChoicesText is the model text of every choice of an /llm response the
// provider adapter returned: content as a string or as parts (text and
// refusal). Tool calls are inspected on their own.
func llmChoicesText(choices []ChatChoice) string {
	var r responseText
	for _, c := range choices {
		if c.Message == nil {
			continue
		}
		if c.Message.Content != "" {
			r.Add(answerPiece(c.Index, c.Message.Content))
			continue
		}
		r.AddAll(chatContentPieces(c.Index, c.Message.RawContent))
	}
	return r.String()
}

// llmToolCalls is the tool calls of every choice, one array.
func llmToolCalls(choices []ChatChoice) json.RawMessage {
	var out json.RawMessage
	for _, c := range choices {
		if c.Message != nil && len(c.Message.ToolCalls) > 0 {
			out = mergeToolCallChunks(out, c.Message.ToolCalls)
		}
	}
	return out
}

// anthropicContentPieces reads Anthropic content blocks: text and thinking.
// tool_use input is inspected as a tool call.
func anthropicContentPieces(body []byte) ([]responsePiece, bool) {
	var resp struct {
		Content []struct {
			Type     string `json:"type"`
			Text     string `json:"text"`
			Thinking string `json:"thinking"`
		} `json:"content"`
	}
	if json.Unmarshal(body, &resp) != nil {
		return nil, false
	}
	var out []responsePiece
	for _, c := range resp.Content {
		switch c.Type {
		case "text":
			out = append(out, answerPiece(0, c.Text))
		case "thinking":
			out = append(out, reasoningPiece(0, c.Thinking))
		}
	}
	return out, true
}

// streamEventPieces reads the model text of one streamed event of provider:
// an SSE data payload, an NDJSON line or a decoded eventstream payload.
// Streamed tool input is model text here: the passthrough stream has no
// separate tool-call check.
func streamEventPieces(data, provider string) []responsePiece {
	switch provider {
	case "anthropic":
		return anthropicStreamPieces([]byte(data))
	case "gemini":
		return geminiPieces([]byte(data), true)
	case "bedrock":
		var ev struct {
			ContentBlockDelta *bedrockStreamDelta `json:"contentBlockDelta"`
		}
		if json.Unmarshal([]byte(data), &ev) != nil || ev.ContentBlockDelta == nil {
			return nil
		}
		return ev.ContentBlockDelta.pieces()
	case "ollama":
		return ollamaPieces([]byte(data), true)
	default:
		var ev struct {
			Type         string            `json:"type"`
			Delta        json.RawMessage   `json:"delta"`
			OutputIndex  int               `json:"output_index"`
			SummaryIndex int               `json:"summary_index"`
			Choices      []chatShapeChoice `json:"choices"`
		}
		if json.Unmarshal([]byte(data), &ev) != nil {
			return nil
		}
		if strings.HasPrefix(ev.Type, "response.") && strings.Contains(ev.Type, ".delta") {
			// OpenAI Responses: every text delta the client receives.
			text := respJSONString(ev.Delta)
			switch {
			case text == "":
				return nil
			case strings.HasPrefix(ev.Type, "response.output_text."):
				return []responsePiece{answerPiece(0, text)}
			case strings.HasPrefix(ev.Type, "response.refusal."):
				return []responsePiece{refusalPiece(0, text)}
			case strings.HasPrefix(ev.Type, "response.reasoning"):
				return []responsePiece{{lane: responseLane{field: responseFieldReasoning, part: ev.OutputIndex}, text: text}}
			default:
				return []responsePiece{toolInputPiece(0, ev.OutputIndex, text)}
			}
		}
		return chatChoicesPieces(ev.Choices, true)
	}
}

func anthropicStreamPieces(data []byte) []responsePiece {
	var ev struct {
		Type  string `json:"type"`
		Index int    `json:"index"`
		Delta struct {
			Text        string `json:"text"`
			Thinking    string `json:"thinking"`
			PartialJSON string `json:"partial_json"`
		} `json:"delta"`
		ContentBlock struct {
			Text     string          `json:"text"`
			Thinking string          `json:"thinking"`
			Input    json.RawMessage `json:"input"`
		} `json:"content_block"`
	}
	if json.Unmarshal(data, &ev) != nil {
		return nil
	}
	switch ev.Type {
	case "content_block_delta":
		return []responsePiece{
			answerPiece(0, ev.Delta.Text),
			reasoningPiece(0, ev.Delta.Thinking),
			toolInputPiece(0, ev.Index, ev.Delta.PartialJSON),
		}
	case "content_block_start":
		return []responsePiece{
			answerPiece(0, ev.ContentBlock.Text),
			reasoningPiece(0, ev.ContentBlock.Thinking),
			toolInputPiece(0, ev.Index, jsonArgsText(ev.ContentBlock.Input)),
		}
	}
	return nil
}

// bedrockStreamDelta is a ConverseStream contentBlockDelta: answer text,
// reasoning text, or a fragment of tool input.
type bedrockStreamDelta struct {
	ContentBlockIndex int `json:"contentBlockIndex"`
	Delta             struct {
		Text             string `json:"text"`
		ReasoningContent struct {
			Text string `json:"text"`
		} `json:"reasoningContent"`
		ToolUse struct {
			Input string `json:"input"`
		} `json:"toolUse"`
	} `json:"delta"`
}

func (d *bedrockStreamDelta) pieces() []responsePiece {
	return []responsePiece{
		answerPiece(0, d.Delta.Text),
		reasoningPiece(0, d.Delta.ReasoningContent.Text),
		toolInputPiece(0, d.ContentBlockIndex, d.Delta.ToolUse.Input),
	}
}

// geminiPieces reads every candidate: answer parts, thought parts, and with
// withTools the functionCall arguments.
func geminiPieces(body []byte, withTools bool) []responsePiece {
	var resp struct {
		Candidates []struct {
			Index   *int `json:"index"`
			Content struct {
				Parts []struct {
					Text         string `json:"text"`
					Thought      bool   `json:"thought"`
					FunctionCall *struct {
						Args json.RawMessage `json:"args"`
					} `json:"functionCall"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if json.Unmarshal(body, &resp) != nil {
		return nil
	}
	var out []responsePiece
	for ci, c := range resp.Candidates {
		choice := ci
		if c.Index != nil {
			choice = *c.Index
		}
		for pi, p := range c.Content.Parts {
			if p.Thought {
				out = append(out, reasoningPiece(choice, p.Text))
			} else {
				out = append(out, answerPiece(choice, p.Text))
			}
			if withTools && p.FunctionCall != nil {
				out = append(out, toolInputPiece(choice, pi, jsonArgsText(p.FunctionCall.Args)))
			}
		}
	}
	return out
}

// ollamaPieces reads native Ollama chat and generate: content or response,
// thinking, and with withTools the tool-call arguments.
func ollamaPieces(body []byte, withTools bool) []responsePiece {
	var resp struct {
		Message struct {
			Content   string `json:"content"`
			Thinking  string `json:"thinking"`
			ToolCalls []struct {
				Function struct {
					Arguments json.RawMessage `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"message"`
		Response string `json:"response"`
		Thinking string `json:"thinking"`
	}
	if json.Unmarshal(body, &resp) != nil {
		return nil
	}
	out := []responsePiece{
		answerPiece(0, resp.Message.Content),
		answerPiece(0, resp.Response),
		reasoningPiece(0, resp.Message.Thinking),
		reasoningPiece(0, resp.Thinking),
	}
	if withTools {
		for i, tc := range resp.Message.ToolCalls {
			out = append(out, toolInputPiece(0, i, jsonArgsText(tc.Function.Arguments)))
		}
	}
	return out
}

// passthroughStreamEventData is the event payload of one stream line: the
// data of an SSE data line (with or without the space after the colon), or
// an NDJSON line whole. ok is false for a line that carries no event.
func passthroughStreamEventData(line string, ndjson bool) (string, bool) {
	line = strings.TrimSpace(line)
	if ndjson {
		return line, line != ""
	}
	data, ok := strings.CutPrefix(line, "data:")
	if !ok {
		return "", false
	}
	data = strings.TrimSpace(data)
	return data, data != "" && data != "[DONE]"
}
