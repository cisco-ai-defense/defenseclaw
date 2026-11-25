// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// The block tail of a refused stream the agent already got part of
// (rel-1-0-10:GAP-1206): the block reaches the agent as the last assistant
// text of the stream under way, in that stream's own wire shape, at the
// content index after the last one the agent got. Held events never went
// out, so they do not count.

// streamTail names the wire shape of the block tail of an SSE or NDJSON
// passthrough stream.
type streamTail int

const (
	streamTailOpenAI         streamTail = iota // Chat Completions or Responses SSE (sseToolCalls.writeSSEBlockTail)
	streamTailAnthropic                        // Anthropic Messages SSE
	streamTailGemini                           // Gemini streamGenerateContent SSE
	streamTailOllamaChat                       // Ollama /api/chat NDJSON
	streamTailOllamaGenerate                   // Ollama /api/generate NDJSON
)

// streamTailOf picks the block tail shape of a passthrough stream.
func streamTailOf(path, provider string, ndjson bool) streamTail {
	if ndjson {
		if strings.HasSuffix(path, "/api/generate") {
			return streamTailOllamaGenerate
		}
		return streamTailOllamaChat
	}
	if a := adapterFor(path, provider); a != nil {
		switch a.Name() {
		case "anthropic":
			return streamTailAnthropic
		case "gemini":
			return streamTailGemini
		}
	}
	return streamTailOpenAI
}

// streamMark is what one queued event changes in the content blocks the
// agent has, once the event is sent.
type streamMark struct {
	msgStart bool // an Anthropic message_start
	start    int  // the Anthropic content block it opens, -1 none
	call     bool // the block it opens is a tool call (isCallType)
	stop     int  // the Anthropic content block it closes, -1 none
	bedrock  int  // the highest Bedrock content index read up to and with this event, -1 none
}

var noStreamMark = streamMark{start: -1, stop: -1, bedrock: -1}

// anthropicStreamMark reads the content block an Anthropic event opens or
// closes. Only an event that names one of those types is decoded.
func anthropicStreamMark(data string) streamMark {
	m := noStreamMark
	if !strings.Contains(data, "message_start") && !strings.Contains(data, "content_block_st") {
		return m
	}
	var ev struct {
		Type  string `json:"type"`
		Index *int   `json:"index"`
		// Block stays raw: a content_block that is not an object (null, a
		// string) must still mark the block the event opens, as a block of
		// no known call type (GAP-1768).
		Block json.RawMessage `json:"content_block"`
	}
	if json.Unmarshal([]byte(data), &ev) != nil {
		return m
	}
	var block struct {
		Type string `json:"type"`
	}
	_ = json.Unmarshal(ev.Block, &block)
	switch {
	case ev.Type == "message_start":
		m.msgStart = true
	case ev.Type == "content_block_start" && ev.Index != nil && *ev.Index >= 0:
		m.start, m.call = *ev.Index, isCallType(block.Type)
	case ev.Type == "content_block_stop" && ev.Index != nil && *ev.Index >= 0:
		m.stop = *ev.Index
	}
	return m
}

// streamSent is what the agent got of the content blocks of the stream.
type streamSent struct {
	msgStart bool
	open     int  // the Anthropic content block opened and not closed, -1 none
	openCall bool // that open block is a tool call
	next     int  // the next free Anthropic content index
	bedrock  int  // the highest Bedrock content index sent, -1 none
}

func newStreamSent() streamSent { return streamSent{open: -1, bedrock: -1} }

// add takes the mark of one event sent to the agent.
func (s *streamSent) add(m streamMark) {
	if m.msgStart {
		s.msgStart = true
	}
	if m.start >= 0 {
		s.open, s.openCall = m.start, m.call
		if m.start >= s.next {
			s.next = m.start + 1
		}
	}
	if m.stop >= 0 && m.stop == s.open {
		s.open, s.openCall = -1, false
	}
	if m.bedrock > s.bedrock {
		s.bedrock = m.bedrock
	}
}

// writeStreamBlockTail ends a partly sent SSE or NDJSON stream with msg as
// its last assistant text, in the stream's own shape.
func writeStreamBlockTail(w http.ResponseWriter, tail streamTail, calls *sseToolCalls, sent streamSent, model, msg string) {
	switch tail {
	case streamTailAnthropic:
		writeAnthropicBlockTail(w, sent, model, msg)
	case streamTailGemini:
		data, _ := json.Marshal(geminiBlockFrame(msg))
		fmt.Fprintf(w, "data: %s\n\n", data)
	case streamTailOllamaChat, streamTailOllamaGenerate:
		body, _ := json.Marshal(ollamaBlockBody(model, msg, tail == streamTailOllamaGenerate))
		_, _ = w.Write(append(body, '\n'))
	default:
		calls.writeSSEBlockTail(w, model, msg)
		return
	}
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

// writeAnthropicBlockTail closes the content block the agent has open, adds
// msg as a text block at the next index the agent did not get, and ends the
// message (end_turn), so the Messages stream stays one valid message.
//
// A tool call block the agent has open (its start and deltas went out with
// an alert, and the call was refused at its content_block_stop) is never
// closed: Claude Code and the AI SDK run a tool_use at its
// content_block_stop with the input they got. That stream ends with an
// Anthropic error event that carries msg, and no message_stop.
func writeAnthropicBlockTail(w io.Writer, sent streamSent, model, msg string) {
	if sent.open >= 0 && sent.openCall {
		raw, _ := json.Marshal(map[string]any{"type": "error", "error": map[string]string{"type": "permission_error", "message": msg}})
		fmt.Fprintf(w, "event: error\ndata: %s\n\n", raw)
		return
	}
	var evs []map[string]any
	if !sent.msgStart {
		evs = append(evs, map[string]any{"type": "message_start", "message": map[string]any{"id": "msg_blocked", "type": "message",
			"role": "assistant", "model": model, "content": []any{}, "usage": map[string]int{"input_tokens": 0}}})
	}
	if sent.open >= 0 {
		evs = append(evs, map[string]any{"type": "content_block_stop", "index": sent.open})
	}
	idx := sent.next
	evs = append(evs,
		map[string]any{"type": "content_block_start", "index": idx, "content_block": map[string]any{"type": "text", "text": ""}},
		map[string]any{"type": "content_block_delta", "index": idx, "delta": map[string]any{"type": "text_delta", "text": msg}},
		map[string]any{"type": "content_block_stop", "index": idx},
		map[string]any{"type": "message_delta", "delta": map[string]any{"stop_reason": "end_turn", "stop_sequence": nil},
			"usage": map[string]int{"output_tokens": 1}},
		map[string]any{"type": "message_stop"},
	)
	for _, ev := range evs {
		raw, _ := json.Marshal(ev)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev["type"], raw)
	}
}
