// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// A streamed passthrough reply (rel-1-0-10:GAP-0212 review round 1): every
// byte the client gets is held by the completion stream guard until the
// guardrail has checked the model text it carries, whatever field carries it
// (answer text, thinking or reasoning text, tool input), and every tool call
// the reply makes is assembled and checked by the tool-call rules before any
// of its frames is sent (GAP-0370). A line past its bound is judged as read
// and counts as truncated under the one bound rule (GAP-0368); SSE data lines
// with or without the space after the colon are read alike.

const (
	// passthroughMaxLineBytes bounds one SSE line the reader holds before its
	// end arrives; past it the line is judged as read (TRUNCATED).
	passthroughMaxLineBytes = 1 << 20
	// passthroughMaxToolBytes bounds the reply bytes held behind an open tool
	// call; past it the calls are checked as read (TRUNCATED).
	passthroughMaxToolBytes = 10 << 20
)

// streamLaneText is model text of one lane (a choice index) in a stream event.
type streamLaneText struct {
	lane int
	text string
}

// streamToolCalls assembles the tool calls of a streamed provider reply in
// the order they start.
type streamToolCalls struct {
	order []string
	calls map[string]*streamToolCall
}

type streamToolCall struct {
	name string
	args strings.Builder
}

func (t *streamToolCalls) call(key string) *streamToolCall {
	if t.calls == nil {
		t.calls = map[string]*streamToolCall{}
	}
	c, ok := t.calls[key]
	if !ok {
		c = &streamToolCall{}
		t.calls[key] = c
		t.order = append(t.order, key)
	}
	return c
}

func (t *streamToolCalls) start(key, name string) {
	if c := t.call(key); name != "" {
		c.name = name
	}
}

func (t *streamToolCalls) add(key, args string) { t.call(key).args.WriteString(args) }

// Any reports a tool call in the reply.
func (t *streamToolCalls) Any() bool { return len(t.order) > 0 }

// JSON is the calls in the nested Chat Completions tool_calls shape that
// inspectToolCalls reads (as extractPassthroughToolCalls emits).
func (t *streamToolCalls) JSON() json.RawMessage {
	if !t.Any() {
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
	out := make([]call, 0, len(t.order))
	for _, key := range t.order {
		c := t.calls[key]
		out = append(out, call{Type: "function", Function: fn{Name: c.name, Arguments: c.args.String()}})
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		return nil
	}
	return encoded
}

// modelStreamState is what a stream's event parser keeps between events.
type modelStreamState struct {
	tools         streamToolCalls
	model         string
	anthropicNext int // the next free Anthropic content block index
}

// sseLineData is the payload of an SSE data line: "data:" followed by the
// payload, the one space after the colon optional (the SSE format).
func sseLineData(line string) (string, bool) {
	line = strings.TrimRight(line, "\r\n")
	payload, ok := strings.CutPrefix(line, "data:")
	if !ok {
		return "", false
	}
	return strings.TrimPrefix(payload, " "), true
}

// modelStreamEvent is the model text of one stream event of provider, per
// lane, with the tool calls it starts or continues recorded in st. Every
// field the client receives as model output counts: answer text, thinking and
// reasoning text, and tool input (also read as text, so a credential in a
// tool argument is found by the content rules too).
func modelStreamEvent(data, provider string, st *modelStreamState) []streamLaneText {
	raw := []byte(data)
	if st.model == "" {
		st.model = responseModelFromRawJSON(raw)
	}
	switch provider {
	case "anthropic":
		return anthropicStreamEvent(raw, st)
	case "gemini":
		return geminiStreamEvent(raw, st)
	case "bedrock":
		return converseStreamEvent("", raw, st)
	case "ollama":
		return ollamaStreamEvent(raw, st)
	}
	return openAIStreamEvent(raw, st)
}

func anthropicStreamEvent(raw []byte, st *modelStreamState) []streamLaneText {
	var ev struct {
		Type         string `json:"type"`
		Index        int    `json:"index"`
		ContentBlock struct {
			Type     string `json:"type"`
			ID       string `json:"id"`
			Name     string `json:"name"`
			Text     string `json:"text"`
			Thinking string `json:"thinking"`
		} `json:"content_block"`
		Delta struct {
			Type        string `json:"type"`
			Text        string `json:"text"`
			Thinking    string `json:"thinking"`
			PartialJSON string `json:"partial_json"`
		} `json:"delta"`
	}
	if json.Unmarshal(raw, &ev) != nil {
		return nil
	}
	if ev.Type == "content_block_start" || ev.Type == "content_block_delta" {
		st.anthropicNext = max(st.anthropicNext, ev.Index+1)
	}
	key := "anthropic:" + strconv.Itoa(ev.Index)
	switch ev.Type {
	case "content_block_start":
		if ev.ContentBlock.Type == "tool_use" || ev.ContentBlock.Type == "server_tool_use" {
			st.tools.start(key, ev.ContentBlock.Name)
			return nil
		}
		return laneTexts(0, ev.ContentBlock.Text+ev.ContentBlock.Thinking)
	case "content_block_delta":
		if ev.Delta.Type == "input_json_delta" {
			st.tools.add(key, ev.Delta.PartialJSON)
			return laneTexts(0, jsonEscapesRead(ev.Delta.PartialJSON))
		}
		return laneTexts(0, ev.Delta.Text+ev.Delta.Thinking)
	}
	return nil
}

func openAIStreamEvent(raw []byte, st *modelStreamState) []streamLaneText {
	var ev struct {
		Type   string `json:"type"`
		Delta  string `json:"delta"`
		ItemID string `json:"item_id"`
		Output int    `json:"output_index"`
		Item   struct {
			Type   string `json:"type"`
			ID     string `json:"id"`
			Name   string `json:"name"`
			Args   string `json:"arguments"`
			CallID string `json:"call_id"`
		} `json:"item"`
		Choices []struct {
			Index int `json:"index"`
			Delta struct {
				Content          string          `json:"content"`
				ReasoningContent string          `json:"reasoning_content"`
				Reasoning        string          `json:"reasoning"`
				Refusal          string          `json:"refusal"`
				ToolCalls        json.RawMessage `json:"tool_calls"`
			} `json:"delta"`
		} `json:"choices"`
	}
	if json.Unmarshal(raw, &ev) != nil {
		return nil
	}
	if strings.HasPrefix(ev.Type, "response.") {
		// Responses API events.
		switch {
		case ev.Type == "response.output_item.added" && ev.Item.Type == "function_call":
			st.tools.start("responses:"+ev.Item.ID, ev.Item.Name)
			if ev.Item.Args != "" {
				st.tools.add("responses:"+ev.Item.ID, ev.Item.Args)
				return laneTexts(0, jsonEscapesRead(ev.Item.Args))
			}
		case ev.Type == "response.function_call_arguments.delta":
			st.tools.add("responses:"+ev.ItemID, ev.Delta)
			return laneTexts(0, jsonEscapesRead(ev.Delta))
		case strings.HasSuffix(ev.Type, ".delta"):
			// output_text, refusal, reasoning_text and reasoning_summary_text.
			return laneTexts(0, ev.Delta)
		}
		return nil
	}
	var out []streamLaneText
	for _, c := range ev.Choices {
		text := c.Delta.Content + c.Delta.ReasoningContent + c.Delta.Reasoning + c.Delta.Refusal
		if len(c.Delta.ToolCalls) > 0 {
			var calls []struct {
				Index    int `json:"index"`
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			}
			if json.Unmarshal(c.Delta.ToolCalls, &calls) == nil {
				for _, tc := range calls {
					key := "openai:" + strconv.Itoa(c.Index) + ":" + strconv.Itoa(tc.Index)
					st.tools.start(key, tc.Function.Name)
					st.tools.add(key, tc.Function.Arguments)
					text += jsonEscapesRead(tc.Function.Arguments)
				}
			}
		}
		if text != "" {
			out = append(out, streamLaneText{lane: c.Index, text: text})
		}
	}
	return out
}

func geminiStreamEvent(raw []byte, st *modelStreamState) []streamLaneText {
	var ev struct {
		Candidates []struct {
			Index   int `json:"index"`
			Content struct {
				Parts []struct {
					Text         string `json:"text"`
					FunctionCall *struct {
						Name string          `json:"name"`
						Args json.RawMessage `json:"args"`
					} `json:"functionCall"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if json.Unmarshal(raw, &ev) != nil {
		return nil
	}
	var out []streamLaneText
	for _, c := range ev.Candidates {
		var text strings.Builder
		for _, part := range c.Content.Parts {
			text.WriteString(part.Text) // thought parts carry their text here too
			if part.FunctionCall != nil {
				key := "gemini:" + strconv.Itoa(c.Index) + ":" + strconv.Itoa(len(st.tools.order))
				st.tools.start(key, part.FunctionCall.Name)
				st.tools.add(key, string(part.FunctionCall.Args))
				text.WriteString(jsonEscapesRead(string(part.FunctionCall.Args)))
			}
		}
		if text.Len() > 0 {
			out = append(out, streamLaneText{lane: c.Index, text: text.String()})
		}
	}
	return out
}

// converseStreamEvent reads a Bedrock Converse stream event; eventType is the
// eventstream :event-type header ("" in an SSE frame, where the event is a
// key of the payload).
func converseStreamEvent(eventType string, raw []byte, st *modelStreamState) []streamLaneText {
	var ev struct {
		ContentBlockIndex int `json:"contentBlockIndex"`
		Start             struct {
			ToolUse struct {
				Name      string `json:"name"`
				ToolUseID string `json:"toolUseId"`
			} `json:"toolUse"`
		} `json:"start"`
		Delta struct {
			Text             string `json:"text"`
			ReasoningContent struct {
				Text string `json:"text"`
			} `json:"reasoningContent"`
			ToolUse struct {
				Input string `json:"input"`
			} `json:"toolUse"`
		} `json:"delta"`
	}
	if eventType == "" {
		var wrapped map[string]json.RawMessage
		if json.Unmarshal(raw, &wrapped) != nil {
			return nil
		}
		for _, name := range []string{"contentBlockStart", "contentBlockDelta"} {
			if inner, ok := wrapped[name]; ok {
				return converseStreamEvent(name, inner, st)
			}
		}
		return nil
	}
	if json.Unmarshal(raw, &ev) != nil {
		return nil
	}
	key := "converse:" + strconv.Itoa(ev.ContentBlockIndex)
	switch eventType {
	case "contentBlockStart":
		if ev.Start.ToolUse.Name != "" {
			st.tools.start(key, ev.Start.ToolUse.Name)
		}
	case "contentBlockDelta":
		text := ev.Delta.Text + ev.Delta.ReasoningContent.Text
		if ev.Delta.ToolUse.Input != "" {
			st.tools.add(key, ev.Delta.ToolUse.Input)
			text += jsonEscapesRead(ev.Delta.ToolUse.Input)
		}
		return laneTexts(0, text)
	}
	return nil
}

func ollamaStreamEvent(raw []byte, st *modelStreamState) []streamLaneText {
	var ev struct {
		Message struct {
			Content   string `json:"content"`
			Thinking  string `json:"thinking"`
			ToolCalls []struct {
				Function struct {
					Name      string          `json:"name"`
					Arguments json.RawMessage `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"message"`
		Response string `json:"response"`
		Thinking string `json:"thinking"`
	}
	if json.Unmarshal(raw, &ev) != nil {
		return nil
	}
	text := ev.Message.Content + ev.Message.Thinking + ev.Response + ev.Thinking
	for _, tc := range ev.Message.ToolCalls {
		key := "ollama:" + strconv.Itoa(len(st.tools.order))
		st.tools.start(key, tc.Function.Name)
		st.tools.add(key, string(tc.Function.Arguments))
		text += jsonEscapesRead(string(tc.Function.Arguments))
	}
	return laneTexts(0, text)
}

func laneTexts(lane int, text string) []streamLaneText {
	if text == "" {
		return nil
	}
	return []streamLaneText{{lane: lane, text: text}}
}

// jsonEscapesRead is JSON text as a reader sees the strings in it: the
// escapes \n \t \r \" \\ \/ and \uXXXX decoded wherever they appear, the
// rest unchanged. It reads a fragment of a JSON document (a streamed tool
// input, a line cut at a bound), which json.Unmarshal cannot.
func jsonEscapesRead(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			b.WriteByte(c)
			continue
		}
		i++
		switch s[i] {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case 'b', 'f':
			b.WriteByte(' ')
		case '"', '\\', '/':
			b.WriteByte(s[i])
		case 'u':
			if i+4 < len(s) {
				if v, err := strconv.ParseUint(s[i+1:i+5], 16, 32); err == nil {
					b.WriteRune(rune(v))
					i += 4
					continue
				}
			}
			b.WriteString(`\u`)
		default:
			b.WriteByte('\\')
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// pushStreamTexts adds the lane texts of one output unit to the guard and
// then the unit (nil: the caller sends it itself), and returns every unit
// released along the way, in order.
func pushStreamTexts(guard *completionStreamGuard, texts []streamLaneText, unit []byte) ([][]byte, *ScanVerdict) {
	var out [][]byte
	for _, t := range texts {
		units, v := guard.PushLane(t.lane, t.text, nil)
		if v != nil {
			return nil, v
		}
		out = append(out, units...)
	}
	lane := 0
	if len(texts) > 0 {
		lane = texts[len(texts)-1].lane
	}
	units, v := guard.PushLane(lane, "", unit)
	if v != nil {
		return nil, v
	}
	return append(out, units...), nil
}

// passthroughStream is the state of one streamed passthrough reply.
type passthroughStream struct {
	p        *GuardrailProxy
	w        http.ResponseWriter
	r        *http.Request
	flusher  http.Flusher
	guard    *completionStreamGuard
	state    modelStreamState
	provider string
	label    string
	mode     string
	model    string
	blockMsg string
	bedrock  *bedrockEventStreamText

	held        [][]byte // released output behind an open tool call
	heldBytes   int
	toolsCapped bool // the tool-call bound was hit: output is no longer held
	toolsDone   bool
	blocked     *ScanVerdict
	blockedTool bool
	refused     bool
}

// streamPassthroughReply streams the reply body through the guard. It
// returns the guard (its text feeds the final post-stream verdict) and false
// when the reply was blocked or refused; the client then has the in-band
// block notice, or nothing more for a refused Bedrock eventstream.
func (p *GuardrailProxy) streamPassthroughReply(w http.ResponseWriter, r *http.Request, body io.Reader,
	bedrock *bedrockEventStreamText, provider, label, mode, model, customBlockMsg string) (*passthroughStream, bool) {
	flusher, _ := w.(http.Flusher)
	s := &passthroughStream{
		p: p, w: w, r: r, flusher: flusher, provider: provider, label: label, mode: mode,
		model: model, blockMsg: customBlockMsg, bedrock: bedrock,
		guard: p.newProxyStreamGuard(r.Context(), r, label, mode),
	}
	if bedrock != nil {
		bedrock.state = &s.state
	}
	buf := make([]byte, 4096)
	var line []byte
	longLine := false
	reported := false
	for s.blocked == nil && !s.refused {
		n, readErr := body.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			if bedrock != nil {
				text := bedrock.Feed(chunk)
				if bedrock.Broken() && !reported {
					reported = true
					if p.uninspectableReply(r.Context(), label, mode, "the event stream could not be framed") {
						s.refused = true
						break
					}
				}
				s.push(laneTexts(0, text), append([]byte(nil), chunk...))
			} else {
				line = append(line, chunk...)
				for s.blocked == nil {
					i := bytes.IndexByte(line, '\n')
					if longLine {
						// The rest of a line past the bound: judged as read.
						end := len(line)
						if i >= 0 {
							end = i + 1
						}
						s.push(laneTexts(0, jsonEscapesRead(validUTF8Prefix(line[:end]))), append([]byte(nil), line[:end]...))
						line = line[end:]
						if i < 0 {
							break
						}
						longLine = false
						continue
					}
					if i < 0 {
						break
					}
					s.pushLine(append([]byte(nil), line[:i+1]...))
					line = line[i+1:]
				}
				if s.blocked == nil && len(line) > passthroughMaxLineBytes {
					// GAP-0368: the line is past its bound before its end:
					// a truncated input, judged on what was read.
					if v := s.guard.Truncate(bounded.Bytes); v != nil {
						s.blocked = v
						break
					}
					longLine = true
					s.push(laneTexts(0, jsonEscapesRead(validUTF8Prefix(line))), append([]byte(nil), line...))
					line = nil
				}
			}
		}
		if readErr != nil {
			break
		}
	}
	if s.refused {
		return s, false
	}
	if s.blocked == nil && len(line) > 0 {
		s.pushLine(append([]byte(nil), line...))
	}
	if s.blocked == nil {
		units, v := s.guard.Finish()
		if v != nil {
			s.blocked = v
		} else {
			s.route(units)
		}
	}
	if s.blocked == nil {
		s.checkTools()
	}
	if s.blocked != nil {
		s.writeBlock()
		return s, false
	}
	writeStreamUnits(w, flusher, s.held)
	s.held = nil
	return s, true
}

// pushLine adds one SSE line (with its newline) and its model text.
func (s *passthroughStream) pushLine(line []byte) {
	var texts []streamLaneText
	if payload, ok := sseLineData(string(line)); ok && payload != "[DONE]" {
		texts = modelStreamEvent(payload, s.provider, &s.state)
	}
	s.push(texts, line)
}

func (s *passthroughStream) push(texts []streamLaneText, unit []byte) {
	if s.blocked != nil {
		return
	}
	units, v := pushStreamTexts(s.guard, texts, unit)
	if v != nil {
		s.blocked = v
		return
	}
	s.route(units)
}

// route sends released units, or holds them behind an open tool call until
// the call has been checked.
func (s *passthroughStream) route(units [][]byte) {
	if len(units) == 0 {
		return
	}
	if !s.state.tools.Any() || s.toolsCapped || s.mode != "action" {
		writeStreamUnits(s.w, s.flusher, units)
		return
	}
	for _, u := range units {
		s.held = append(s.held, u)
		s.heldBytes += len(u)
	}
	if s.heldBytes <= passthroughMaxToolBytes {
		return
	}
	// Past the tool-call bound: check the calls as read; the pack decides
	// whether a truncated call blocks (strict) or alerts.
	if v := s.guard.Truncate(bounded.Bytes); v != nil {
		s.blocked = v
		return
	}
	s.checkTools()
	if s.blocked != nil {
		return
	}
	s.toolsCapped = true
	writeStreamUnits(s.w, s.flusher, s.held)
	s.held, s.heldBytes = nil, 0
}

// checkTools runs the tool-call rules on the calls the reply made.
func (s *passthroughStream) checkTools() {
	if s.toolsDone || !s.state.tools.Any() {
		return
	}
	s.toolsDone = true
	verdict := s.p.inspectToolCalls(s.r.Context(), s.state.tools.JSON())
	if verdict == nil {
		return
	}
	block := verdict.Action == guardrailActionBlock && s.mode == "action"
	s.p.recordTelemetry(s.r.Context(), "tool-call", s.label, verdict, 0, s.mode, block)
	if block {
		s.blocked, s.blockedTool = verdict, true
	}
}

// writeBlock logs and records the block and ends the reply in band: the
// client gets the block notice in its own stream format, never a bare stop.
func (s *passthroughStream) writeBlock() {
	kind := "completion"
	if s.blockedTool {
		kind = "tool_call"
	} else {
		fmt.Fprintf(os.Stderr, "[guardrail] PASSTHROUGH-STREAM-BLOCK severity=%s %s (%d bytes held back and not sent)\n",
			s.blocked.Severity, logDisplayReason(s.blocked.Reason), s.guard.Held())
		s.p.recordTelemetry(s.r.Context(), "completion", s.label, s.blocked, 0, s.mode, true)
	}
	s.p.enqueueBlockNotification(s.blocked, kind, s.model)
	if s.bedrock != nil {
		return // the AWS eventstream has no text frame the proxy can add
	}
	writePassthroughStreamNotice(s.w, s.flusher, s.provider, s.model, s.state.anthropicNext,
		blockMessage(s.blockMsg, kind, s.blocked.Reason))
}

// writePassthroughStreamNotice ends a provider stream with msg as model
// text and the provider's end-of-stream event.
func writePassthroughStreamNotice(w http.ResponseWriter, flusher http.Flusher, provider, model string, anthropicIndex int, msg string) {
	text := "\n\n" + msg
	var events []string
	frame := func(event string, payload interface{}) {
		data, _ := json.Marshal(payload)
		if event != "" {
			events = append(events, "event: "+event+"\ndata: "+string(data)+"\n\n")
		} else {
			events = append(events, "data: "+string(data)+"\n\n")
		}
	}
	switch provider {
	case "anthropic":
		frame("content_block_start", map[string]interface{}{"type": "content_block_start", "index": anthropicIndex,
			"content_block": map[string]string{"type": "text", "text": ""}})
		frame("content_block_delta", map[string]interface{}{"type": "content_block_delta", "index": anthropicIndex,
			"delta": map[string]string{"type": "text_delta", "text": text}})
		frame("content_block_stop", map[string]interface{}{"type": "content_block_stop", "index": anthropicIndex})
		frame("message_delta", map[string]interface{}{"type": "message_delta",
			"delta": map[string]interface{}{"stop_reason": "end_turn", "stop_sequence": nil}, "usage": map[string]int{"output_tokens": 0}})
		frame("message_stop", map[string]string{"type": "message_stop"})
	case "gemini":
		frame("", map[string]interface{}{"candidates": []map[string]interface{}{{
			"content":      map[string]interface{}{"parts": []map[string]string{{"text": text}}, "role": "model"},
			"finishReason": "SAFETY", "index": 0}}})
	default:
		frame("", map[string]interface{}{"id": "chatcmpl-blocked", "object": "chat.completion.chunk", "model": model,
			"choices": []map[string]interface{}{{"index": 0, "delta": map[string]string{"content": text}, "finish_reason": "stop"}}})
		events = append(events, "data: [DONE]\n\n")
	}
	for _, e := range events {
		_, _ = io.WriteString(w, e)
	}
	if flusher != nil {
		flusher.Flush()
	}
}

// validUTF8Prefix is b as a string, cut before a rune split at its end.
func validUTF8Prefix(b []byte) string {
	end := len(b)
	for i := 0; i < utf8.UTFMax && end > 0; i++ {
		if utf8.Valid(b[:end]) {
			break
		}
		end--
	}
	return string(b[:end])
}
