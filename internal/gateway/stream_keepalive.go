// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"
)

// The client side of the open-run hold (rel-1-0-10:GAP-1307).
//
// A token or a digit run still running at the end of the reply text has no
// idle clock (GAP-1265): the frames behind it wait for the next text or the
// end of the stream, and no byte of the run goes out before a check has read
// it whole (GAP-0429, GAP-1091). While the upstream is quiet there (a long
// server-tool phase, Bedrock throttling, long thinking) the client got no
// byte at all, which trips a client stream-idle watchdog; rel sends those
// bytes at once. After streamKeepAliveAfter with no new text each route now
// does one of two things, and keeps the run held until its verdict:
//
//   - (a) it sends a keep-alive that carries no reply text and keeps holding,
//     again every streamKeepAliveAfter:
//   - the /llm proxy and the raw forward (OpenAI chat SSE): an SSE
//     comment line;
//   - passthrough SSE (OpenAI chat and Responses, Gemini): an SSE comment
//     line; Anthropic Messages: its own ping event once message_start is
//     out (an SSE comment before it, which the SDKs drop);
//   - passthrough Ollama (NDJSON): an empty-content chunk of the same
//     endpoint shape, done false;
//   - passthrough Bedrock InvokeModelWithResponseStream for an Anthropic
//     model, once an event is out: a chunk frame carrying the Anthropic
//     ping event.
//   - (b) where the framing has no content-free event, it checks the held
//     text, then releases the held events with the bytes of the open run
//     masked ('*' for each letter and digit), never raw: Bedrock
//     ConverseStream, InvokeModelWithResponseStream for another model, and
//     an Anthropic invoke stream before its first event went out (a ping
//     before message_start breaks the SDK). Only when rel would have sent
//     those events (past the initial buffer). The run stays open: what
//     follows it is held again, and the check reads it whole with the rest.
//     An event that cannot be rewritten keeps everything held, as before.
//
// An open private-key block keeps its own TRUNCATED idle bound (GAP-0429).

// streamKeepAliveAfter is the quiet time behind an open run before the
// client gets a keep-alive or the masked held events: the idle bound of the
// parent hold (streamHoldMaxPartialAge).
const streamKeepAliveAfter = streamHoldMaxPartialAge

// sseKeepAlive is an SSE comment line: every SSE parser drops it.
var sseKeepAlive = []byte(": keep-alive\n\n")

// anthropicSSEPing is the ping event of the Anthropic Messages stream.
var anthropicSSEPing = []byte("event: ping\ndata: {\"type\": \"ping\"}\n\n")

// laterTime is the later of a and b.
func laterTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// keepAlive is the content-free event of this stream's framing (option a),
// nil when it has none (option b). started: an event of the stream has
// gone out.
func (s *passthroughStream) keepAlive(started bool) []byte {
	switch {
	case s.ndjson:
		chunk := map[string]any{"model": s.model, "created_at": time.Now().UTC().Format(time.RFC3339Nano), "done": false}
		if strings.HasSuffix(s.path, "/api/generate") {
			chunk["response"] = ""
		} else {
			chunk["message"] = map[string]any{"role": "assistant", "content": ""}
		}
		b, err := json.Marshal(chunk)
		if err != nil {
			return nil
		}
		return append(b, '\n')
	case s.bedrock != nil:
		anthropic := bedrockAnthropicModel(s.model) || bedrockAnthropicModel(s.path) || bedrockAnthropicModel(s.bedrock.model)
		if !started || s.bedrock.converse || !anthropic {
			return nil
		}
		var buf bytes.Buffer
		ping := base64.StdEncoding.EncodeToString([]byte(`{"type":"ping"}`))
		if writeBedrockEventStreamFrame(&buf, "chunk", map[string]any{"bytes": ping}) != nil {
			return nil
		}
		return buf.Bytes()
	case s.provider == "anthropic" && started:
		return anthropicSSEPing
	}
	return sseKeepAlive
}

// openRun is the token or digit run still running at the end of one lane.
type openRun struct {
	lane, start int
	text        string
}

// OpenRuns is the open token or digit run of every lane that has one.
func (r *responseText) OpenRuns() []openRun {
	var out []openRun
	for i, l := range r.lanes {
		t := l.String()
		if st := r.secret[i].tokenStart(t); st >= 0 {
			out = append(out, openRun{lane: i, start: st, text: t[st:]})
		}
	}
	return out
}

// maskRunText masks every letter and digit of s.
func maskRunText(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, c := range s {
		if unicode.IsLetter(c) || unicode.IsDigit(c) || c == utf8.RuneError {
			b.WriteByte('*')
		} else {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// runMask is the part of each open run not yet found in the events read
// back to front.
type runMask struct {
	runs []openRun
	left []string
}

func newRunMask(runs []openRun) *runMask {
	m := &runMask{runs: runs, left: make([]string, len(runs))}
	for i, r := range runs {
		m.left[i] = r.text
	}
	return m
}

// mask masks the end of one run in s, a string of an event read back to
// front: all of s when it is the end of what is left of a run, its end when
// the run starts inside it.
func (m *runMask) mask(s string) (string, bool) {
	if s == "" {
		return s, false
	}
	for i, l := range m.left {
		switch {
		case l == "":
		case strings.HasSuffix(l, s):
			m.left[i] = l[:len(l)-len(s)]
			return maskRunText(s), true
		case strings.HasSuffix(s, l):
			m.left[i] = ""
			return s[:len(s)-len(l)] + maskRunText(l), true
		}
	}
	return s, false
}

// jsonSpan is one string literal of a JSON text.
type jsonSpan struct {
	start, end int
	key        bool
}

// jsonStringSpans lists the string literals of the valid JSON text b.
func jsonStringSpans(b []byte) []jsonSpan {
	var out []jsonSpan
	for i := 0; i < len(b); i++ {
		if b[i] != '"' {
			continue
		}
		j := i + 1
		for j < len(b) && b[j] != '"' {
			if b[j] == '\\' {
				j++
			}
			j++
		}
		if j >= len(b) {
			return out
		}
		k := j + 1
		for k < len(b) && (b[k] == ' ' || b[k] == '\t' || b[k] == '\n' || b[k] == '\r') {
			k++
		}
		out = append(out, jsonSpan{start: i, end: j + 1, key: k < len(b) && b[k] == ':'})
		i = j
	}
	return out
}

// maskJSON masks the open runs in the string values of the JSON text b,
// back to front; a "bytes" value (a Bedrock invoke chunk) is read as the
// base64 of the JSON event it carries. False: b is not JSON.
func (m *runMask) maskJSON(b []byte) ([]byte, bool) {
	if !json.Valid(b) {
		return nil, false
	}
	spans := jsonStringSpans(b)
	out := b
	for i := len(spans) - 1; i >= 0; i-- {
		sp := spans[i]
		if sp.key {
			continue
		}
		var s string
		if json.Unmarshal(b[sp.start:sp.end], &s) != nil {
			return nil, false
		}
		var repl string
		changed := false
		var k string
		if i > 0 && spans[i-1].key && string(bytes.TrimSpace(b[spans[i-1].end:sp.start])) == ":" {
			_ = json.Unmarshal(b[spans[i-1].start:spans[i-1].end], &k)
		}
		if inner, err := base64.StdEncoding.DecodeString(s); k == "bytes" && err == nil && json.Valid(inner) {
			mi, ok := m.maskJSON(inner)
			if !ok {
				return nil, false
			}
			if !bytes.Equal(mi, inner) {
				repl, changed = base64.StdEncoding.EncodeToString(mi), true
			}
		} else {
			repl, changed = m.mask(s)
		}
		if !changed {
			continue
		}
		enc, err := json.Marshal(repl)
		if err != nil {
			return nil, false
		}
		out = append(append(append([]byte(nil), out[:sp.start]...), enc...), out[sp.end:]...)
	}
	return out, true
}

// maskBedrockFrames masks the open runs in the whole eventstream frames
// raw, back to front. False: a frame is not one or its payload not JSON.
func (m *runMask) maskBedrockFrames(raw []byte) ([]byte, bool) {
	dec := eventstream.NewDecoder()
	r := bytes.NewReader(raw)
	var msgs []eventstream.Message
	for r.Len() > 0 {
		msg, err := dec.Decode(r, nil)
		if err != nil {
			return nil, false
		}
		msgs = append(msgs, msg)
	}
	changed := false
	for i := len(msgs) - 1; i >= 0; i-- {
		p, ok := m.maskJSON(msgs[i].Payload)
		if !ok {
			return nil, false
		}
		if !bytes.Equal(p, msgs[i].Payload) {
			msgs[i].Payload, changed = p, true
		}
	}
	if !changed {
		return raw, true
	}
	var out bytes.Buffer
	enc := eventstream.NewEncoder()
	for _, msg := range msgs {
		if enc.Encode(&out, msg) != nil {
			return nil, false
		}
	}
	return out.Bytes(), true
}

// maskHeld returns the first n events of the queue with the bytes of the
// open runs masked (option b; Bedrock framing only). Every run must be
// found whole in the queue, or its start in what an earlier masked release
// sent (masked: lane to the run start and end it covered); else false and
// nothing may go out.
func (s *passthroughStream) maskHeld(queue [][]byte, n int, runs []openRun, masked map[int][2]int) ([][]byte, bool) {
	if s.bedrock == nil || len(runs) == 0 {
		return nil, false
	}
	m := newRunMask(runs)
	out := make([][]byte, n)
	for i := len(queue) - 1; i >= 0; i-- {
		ev, ok := m.maskBedrockFrames(queue[i])
		if !ok {
			return nil, false
		}
		if i < n {
			out[i] = ev
		}
	}
	for i, l := range m.left {
		if l == "" {
			continue
		}
		prev, ok := masked[runs[i].lane]
		if !ok || prev[0] != runs[i].start || runs[i].start+len(l) > prev[1] {
			return nil, false
		}
	}
	return out, true
}
