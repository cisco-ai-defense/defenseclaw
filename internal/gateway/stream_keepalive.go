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
//     masked ('*' for each letter and digit), never raw, only for
//     unsigned providers. Signed Bedrock reasoning remains queued intact.
//     Only when rel would have sent those events (past the initial buffer).
//     The run stays open: what follows it is held again, and the check reads
//     it whole with the rest. An event that cannot be rewritten stays held.
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

// openRun is the token or digit run still running at the end of one lane:
// lane is the lane's place in the text, key the lane the reader puts it in.
type openRun struct {
	lane, start int
	key         responseLane
	text        string
}

// OpenRuns is the open token or digit run of every lane that has one.
func (r *responseText) OpenRuns() []openRun {
	keys := make([]responseLane, len(r.lanes))
	for k, i := range r.index {
		keys[i] = k
	}
	var out []openRun
	for i, l := range r.lanes {
		t := l.String()
		if st := r.secret[i].tokenStart(t); st >= 0 {
			out = append(out, openRun{lane: i, start: st, key: keys[i], text: t[st:]})
		}
	}
	return out
}

// ParkedReasoningRuns returns only unresolved runs in reasoning lanes. The
// wire hold may mask these runs while releasing answer events (GAP-2170).
func (r *responseText) ParkedReasoningRuns() []openRun {
	var out []openRun
	for _, run := range r.OpenRuns() {
		if run.key.field == responseFieldReasoning && r.secret[run.lane].parked {
			out = append(out, run)
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

// runTextKeys are the keys of the string fields the typed readers of a
// Bedrock event take (bedrockStreamDelta, bedrockInvokeChunkPieces:
// anthropicStreamPieces, chatChoicesPieces, Mistral outputs; generation,
// outputText, completion, text). A run in a typed lane is looked for only
// in those; delta covers OpenAI Responses reasoning deltas. A run in the walker's lane (responseFieldOther) only in the
// other strings the walker reads. The padding of a frame ("p"), its event
// type or other metadata never holds a typed run: when a padding value
// ended like the run, it took the match and the start of the run went out
// raw (rel-1-0-10:GAP-1320).
var runTextKeys = map[string]bool{"text": true, "thinking": true, "partial_json": true, "input": true,
	"generation": true, "outputText": true, "completion": true, "content": true, "reasoning_content": true, "delta": true,
	"refusal": true, "arguments": true}

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
// front under key: all of s when it is the end of what is left of a run,
// its end when the run starts inside it. Only a run of the lane kind the
// key feeds is looked for (runTextKeys).
func (m *runMask) mask(key, s string) (string, bool) {
	if s == "" {
		return s, false
	}
	typed := runTextKeys[key]
	if !typed && walkSkipScalar[normKey(key)] {
		return s, false
	}
	for i, l := range m.left {
		switch {
		case l == "", (m.runs[i].key.field == responseFieldOther) == typed:
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
// back to front. chunk: b is the payload of a Bedrock invoke chunk, whose
// only text is its "bytes" value, read as the base64 of the JSON event it
// carries (the reader reads no other string of it). False: b is not JSON.
func (m *runMask) maskJSON(b []byte, chunk bool) ([]byte, bool) {
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
		switch {
		case chunk && k == "bytes":
			inner, err := base64.StdEncoding.DecodeString(s)
			if err != nil || !json.Valid(inner) {
				return nil, false
			}
			mi, ok := m.maskJSON(inner, false)
			if !ok {
				return nil, false
			}
			if !bytes.Equal(mi, inner) {
				repl, changed = base64.StdEncoding.EncodeToString(mi), true
			}
		case !chunk:
			repl, changed = m.mask(k, s)
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

// maskSSEEvent masks a single complete SSE or NDJSON event. Events whose
// data spans multiple wire lines stay held: replacing them could change
// the provider grammar, so the caller fails closed.
func (m *runMask) maskSSEEvent(raw []byte, ndjson bool) ([]byte, bool) {
	f := &sseFramer{ndjson: ndjson}
	events := f.Write(raw, false)
	if len(events) != 1 || len(f.Held()) != 0 || events[0].Unread {
		return nil, false
	}
	ev := events[0]
	if !ev.HasData || ev.Data == "[DONE]" {
		return raw, true
	}
	data := []byte(ev.Data)
	if !json.Valid(data) || bytes.Count(raw, data) != 1 {
		return nil, false
	}
	masked, ok := m.maskJSON(data, false)
	if !ok {
		return nil, false
	}
	if bytes.Equal(masked, data) {
		return raw, true
	}
	return bytes.Replace(raw, data, masked, 1), true
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
		var mtype, etype string
		for _, h := range msgs[i].Headers {
			switch h.Name {
			case ":message-type":
				mtype = h.Value.String()
			case ":event-type":
				etype = h.Value.String()
			}
		}
		if mtype != "event" {
			continue // the reader takes no text from it (messagePieces)
		}
		p, ok := m.maskJSON(msgs[i].Payload, etype == "chunk")
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
// open runs masked. Every run must be
// found whole in the queue, or its start in what an earlier masked release
// sent (masked: lane to the run start and end it covered), and the stream's
// own reader must read the masked events as the held ones with only the
// runs masked (maskedAsRead); else false and nothing may go out.
func (s *passthroughStream) maskHeld(queue [][]byte, n int, runs []openRun, masked map[int][2]int) ([][]byte, bool) {
	if len(runs) == 0 {
		return nil, false
	}
	m := newRunMask(runs)
	out := make([][]byte, len(queue))
	for i := len(queue) - 1; i >= 0; i-- {
		var ev []byte
		var ok bool
		if s.bedrock != nil {
			ev, ok = m.maskBedrockFrames(queue[i])
		} else {
			ev, ok = m.maskSSEEvent(queue[i], s.ndjson)
		}
		if !ok {
			return nil, false
		}
		out[i] = ev
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
	if !s.maskedAsRead(queue, out, runs, masked) {
		return nil, false
	}
	return out[:n:n], true
}

// bedrockLaneText is the model text of the whole eventstream frames by
// lane, as the stream's reader takes it (a fresh one with the same value
// cap). False: the frames do not decode whole.
func (s *passthroughStream) bedrockLaneText(frames [][]byte) (map[responseLane]string, bool) {
	rd := newBedrockEventStreamText()
	rd.maxValues = s.bedrock.maxValues
	lanes := map[responseLane]*strings.Builder{}
	for _, f := range frames {
		for _, p := range rd.Feed(f) {
			if p.text == "" {
				continue
			}
			if lanes[p.lane] == nil {
				lanes[p.lane] = &strings.Builder{}
			}
			lanes[p.lane].WriteString(p.text)
		}
	}
	if rd.Broken() || rd.PartialLen() != 0 {
		return nil, false
	}
	out := make(map[responseLane]string, len(lanes))
	for k, b := range lanes {
		out[k] = b.String()
	}
	return out, true
}

// sseLaneText reads complete SSE or NDJSON events with the same typed
// reader used by passthrough_stream.go, for mask validation.
func (s *passthroughStream) sseLaneText(frames [][]byte) (map[responseLane]string, bool) {
	f := &sseFramer{ndjson: s.ndjson}
	calls := newSSEToolCalls(s.p.maxBodyValues())
	var acc responseText
	model := ""
	for _, raw := range frames {
		events := f.Write(raw, false)
		if len(events) != 1 || events[0].Unread || s.eventContent(events[0], calls, &acc, &model) != "" {
			return nil, false
		}
	}
	if len(f.Held()) != 0 {
		return nil, false
	}
	out := make(map[responseLane]string, len(acc.index))
	for lane, i := range acc.index {
		out[lane] = acc.lanes[i].String()
	}
	return out, true
}

func (s *passthroughStream) laneTextForMask(frames [][]byte) (map[responseLane]string, bool) {
	if s.bedrock != nil {
		return s.bedrockLaneText(frames)
	}
	return s.sseLaneText(frames)
}

// maskedAsRead reports that the stream's reader takes from the masked
// frames out the same text as from the held ones, lane by lane, except the
// part of each open run they hold, which it reads with no letter or digit
// left; the part of a run before them went out masked before (prior). A
// run placed in a field of another lane, or a lane that changed otherwise,
// keeps everything held (rel-1-0-10:GAP-1320). The walker's lane is
// compared only when a run is open in it: no string of it is masked
// otherwise (runMask.mask), but which of its strings a typed field holds,
// and so leaves out of it, changes when that field is masked.
func (s *passthroughStream) maskedAsRead(held, out [][]byte, runs []openRun, prior map[int][2]int) bool {
	want, ok := s.laneTextForMask(held)
	if !ok {
		return false
	}
	got, ok := s.laneTextForMask(out)
	if !ok {
		return false
	}
	return maskedLaneTextAsRead(want, got, runs, prior)
}

// maskedLaneTextAsRead checks that only the selected run changed, using
// the provider reader that produced each map.
func maskedLaneTextAsRead(want, got map[responseLane]string, runs []openRun, prior map[int][2]int) bool {
	for k := range got {
		if _, ok := want[k]; !ok && k.field != responseFieldOther {
			return false
		}
	}
	raw := make(map[responseLane]int, len(want)) // bytes at the start of a lane read raw
	for k, t := range want {
		raw[k] = len(t)
	}
	for _, r := range runs {
		t := want[r.key]
		n := min(len(r.text), len(t))
		if !strings.HasSuffix(t, r.text[len(r.text)-n:]) {
			return false
		}
		if n < len(r.text) {
			p, ok := prior[r.lane]
			if !ok || p[0] != r.start || r.start+len(r.text)-n > p[1] {
				return false
			}
		}
		if n > 0 {
			raw[r.key] = len(t) - n
		}
	}
	for k, t := range want {
		if k.field == responseFieldOther && raw[k] == len(t) {
			continue
		}
		g, ok := got[k]
		if !ok || !strings.HasPrefix(g, t[:raw[k]]) {
			return false
		}
		rest := g[raw[k]:]
		if raw[k] == len(t) {
			if rest != "" {
				return false
			}
			continue
		}
		if strings.IndexFunc(rest, func(c rune) bool { return unicode.IsLetter(c) || unicode.IsDigit(c) }) >= 0 {
			return false
		}
	}
	return true
}

// rawForwardLaneText reads OpenAI chat frames as raw-forward does, with
// one lane per choice and field, for safe masking of a parked reasoning run.
func rawForwardLaneText(frames [][]byte) map[responseLane]string {
	var acc responseText
	for _, frame := range frames {
		for _, payload := range rawForwardSSEDataPayloads(frame) {
			if payload == "[DONE]" {
				continue
			}
			pieces, _, _ := parseRawForwardSSEPayload(payload)
			acc.AddAll(pieces)
		}
	}
	out := make(map[responseLane]string, len(acc.index))
	for lane, i := range acc.index {
		out[lane] = acc.lanes[i].String()
	}
	return out
}

// maskRawForwardReasoning masks only unresolved reasoning bytes in queued
// OpenAI chat frames. The raw-forward reader must see no other text change.
func maskRawForwardReasoning(frames [][]byte, runs []openRun, prior map[int][2]int) ([][]byte, bool) {
	if len(runs) == 0 {
		return nil, false
	}
	m := newRunMask(runs)
	out := make([][]byte, len(frames))
	for i := len(frames) - 1; i >= 0; i-- {
		ev, ok := m.maskSSEEvent(frames[i], false)
		if !ok {
			return nil, false
		}
		out[i] = ev
	}
	for i, left := range m.left {
		if left == "" {
			continue
		}
		prev, ok := prior[runs[i].lane]
		if !ok || prev[0] != runs[i].start || runs[i].start+len(left) > prev[1] {
			return nil, false
		}
	}
	if !maskedLaneTextAsRead(rawForwardLaneText(frames), rawForwardLaneText(out), runs, prior) {
		return nil, false
	}
	return out, true
}
