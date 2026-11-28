// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	mrand "math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The tail of a streamed completion (rel-1-0-10:GAP-0212): the bytes after
// the last mid-stream scan are held until a check covers them, the final
// post-stream check is enforced in action mode, observe mode changes
// nothing, and the hold is bounded in time and bytes. The finding is a
// benign marker that a stub inspector flags, so no detection text is needed.
// Every passthrough format: Anthropic, OpenAI Responses, Gemini SSE and the
// Bedrock eventstream (rel-1-0-10:GAP-0629).

const streamTailMarker = "zq-tail-marker-7f3a"

// streamTailInspector flags the marker in the final check (Inspect) and/or
// the mid-stream check (InspectMidStream).
type streamTailInspector struct {
	*mockInspector
	mid, final bool
	mu         sync.Mutex
	finals     int
}

func (i *streamTailInspector) verdict(direction, content string, on bool) *ScanVerdict {
	if direction == "completion" && on && strings.Contains(content, streamTailMarker) {
		return &ScanVerdict{Action: "block", Severity: "HIGH", Reason: "stream tail marker", Findings: []string{"test:stream-tail"}}
	}
	return &ScanVerdict{Action: "allow", Severity: "NONE"}
}

func (i *streamTailInspector) Inspect(_ context.Context, direction, content string, _ []ChatMessage, _, _ string) *ScanVerdict {
	if direction == "completion" {
		i.mu.Lock()
		i.finals++
		i.mu.Unlock()
	}
	return i.verdict(direction, content, i.final)
}

func (i *streamTailInspector) InspectMidStream(_ context.Context, direction, content string, _ []ChatMessage, _, _ string) *ScanVerdict {
	return i.verdict(direction, content, i.mid)
}

const (
	streamTailSSE         = "text/event-stream"
	streamTailEventStream = "application/vnd.amazon.eventstream"
	streamTailNDJSON      = "application/x-ndjson"
)

// streamTailFormat is one wire format of a provider-native stream (SSE,
// native Ollama NDJSON, or the binary Bedrock eventstream held in a string).
type streamTailFormat struct {
	name, provider, path, ctype string
	head, tail                  string // events before the first and after the last text delta
	terminal                    string // the event that ends the stream
	delta                       func(text string) string
}

func streamTailJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// streamTailFrame is one Bedrock InvokeModelWithResponseStream chunk frame
// carrying an Anthropic event.
func streamTailFrame(event string) string {
	var buf bytes.Buffer
	payload, _ := json.Marshal(map[string]string{"bytes": base64.StdEncoding.EncodeToString([]byte(event))})
	_ = eventstream.NewEncoder().Encode(&buf, eventstream.Message{Headers: eventstream.Headers{
		{Name: ":message-type", Value: eventstream.StringValue("event")},
		{Name: ":event-type", Value: eventstream.StringValue("chunk")},
		{Name: ":content-type", Value: eventstream.StringValue("application/json")},
	}, Payload: payload})
	return buf.String()
}

// streamTailGeminiEvent is one Gemini streamGenerateContent SSE event with
// the given parts for candidate index (CRLF framing, as the API sends).
func streamTailGeminiEvent(index int, parts []any, extra map[string]any) string {
	cand := map[string]any{"content": map[string]any{"role": "model", "parts": parts}, "index": index}
	for k, v := range extra {
		cand[k] = v
	}
	return "data: " + streamTailJSON(map[string]any{"candidates": []any{cand}}) + "\r\n\r\n"
}

var streamTailFormats = []streamTailFormat{
	{
		name: "anthropic", provider: "anthropic", path: "/v1/messages", ctype: streamTailSSE,
		head: "event: message_start\ndata: " + streamTailJSON(map[string]any{"type": "message_start", "message": map[string]any{"id": "msg_1", "model": "claude-test"}}) + "\n\n" +
			"event: content_block_start\ndata: " + streamTailJSON(map[string]any{"type": "content_block_start", "index": 0, "content_block": map[string]any{"type": "text", "text": ""}}) + "\n\n",
		tail: "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n" +
			"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"}}\n\n",
		terminal: "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
		delta: func(text string) string {
			return "event: content_block_delta\ndata: " + streamTailJSON(map[string]any{"type": "content_block_delta", "index": 0, "delta": map[string]any{"type": "text_delta", "text": text}}) + "\n\n"
		},
	},
	{
		name: "openai-responses", provider: "openai", path: "/v1/responses", ctype: streamTailSSE,
		head:     "event: response.created\ndata: " + streamTailJSON(map[string]any{"type": "response.created", "response": map[string]any{"id": "resp_1", "model": "gpt-test"}}) + "\n\n",
		tail:     "event: response.output_text.done\ndata: {\"type\":\"response.output_text.done\",\"item_id\":\"msg_1\"}\n\n",
		terminal: "event: response.completed\ndata: " + streamTailJSON(map[string]any{"type": "response.completed", "response": map[string]any{"id": "resp_1", "status": "completed"}}) + "\n\n",
		delta: func(text string) string {
			return "event: response.output_text.delta\ndata: " + streamTailJSON(map[string]any{"type": "response.output_text.delta", "item_id": "msg_1", "delta": text}) + "\n\n"
		},
	},
	{
		name: "gemini", provider: "gemini", path: "/v1beta/models/gemini-test:streamGenerateContent?alt=sse", ctype: streamTailSSE,
		terminal: streamTailGeminiEvent(0, []any{map[string]any{"text": ""}}, map[string]any{"finishReason": "STOP"}),
		delta: func(text string) string {
			return streamTailGeminiEvent(0, []any{map[string]any{"text": text}}, nil)
		},
	},
	{
		name: "bedrock", provider: "bedrock", path: "/model/anthropic.claude-test-v1:0/invoke-with-response-stream", ctype: streamTailEventStream,
		head:     streamTailFrame(`{"type":"message_start","message":{"id":"msg_1","model":"claude-test"}}`),
		tail:     streamTailFrame(`{"type":"content_block_stop","index":0}`) + streamTailFrame(`{"type":"message_delta","delta":{"stop_reason":"end_turn"}}`),
		terminal: streamTailFrame(`{"type":"message_stop"}`),
		delta: func(text string) string {
			return streamTailFrame(`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":` + streamTailJSON(text) + `}}`)
		},
	},
	{
		// Native Ollama /api/chat: one JSON event per line, streamed through
		// passthroughStream (sseFramer ndjson mode, GAP-0370; GAP-0322).
		name: "ollama", provider: "ollama", path: "/api/chat", ctype: streamTailNDJSON,
		terminal: `{"model":"llama3","message":{"role":"assistant","content":""},"done":true}` + "\n",
		delta: func(text string) string {
			return `{"model":"llama3","message":{"role":"assistant","content":` + streamTailJSON(text) + `},"done":false}` + "\n"
		},
	},
}

// streamTailFormatNamed is the format named name.
func streamTailFormatNamed(t *testing.T, name string) streamTailFormat {
	t.Helper()
	for _, f := range streamTailFormats {
		if f.name == name {
			return f
		}
	}
	t.Fatalf("no stream format %q", name)
	return streamTailFormat{}
}

// streamTailDeltas is benign prose of n bytes cut into deltas of size bytes,
// with extra appended as the last delta(s).
func streamTailDeltas(n, size int, extra ...string) []string {
	text := streamTailProse(n)
	var out []string
	for len(text) > 0 {
		k := min(size, len(text))
		out = append(out, text[:k])
		text = text[k:]
	}
	return append(out, extra...)
}

// streamTailProse is n bytes of benign prose.
func streamTailProse(n int) string {
	const prose = "the stream carries plain words about lists and maps and loops. "
	return strings.Repeat(prose, n/len(prose)+1)[:n]
}

// streamTailUpstream serves one stream: head, the deltas, tail and terminal.
// stall (when not nil) is waited on before the tail: the upstream goes idle
// with the connection open.
func streamTailUpstream(t *testing.T, f streamTailFormat, deltas []string, gap time.Duration, stall <-chan struct{}) (*httptest.Server, string) {
	t.Helper()
	var whole strings.Builder
	whole.WriteString(f.head)
	for _, d := range deltas {
		whole.WriteString(f.delta(d))
	}
	whole.WriteString(f.tail + f.terminal)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", f.ctype)
		w.WriteHeader(http.StatusOK)
		fl := w.(http.Flusher)
		write := func(s string) {
			_, _ = io.WriteString(w, s)
			fl.Flush()
		}
		write(f.head)
		for _, d := range deltas {
			if gap > 0 {
				time.Sleep(gap)
			}
			write(f.delta(d))
		}
		if stall != nil {
			select {
			case <-stall:
			case <-r.Context().Done():
				return
			}
		}
		write(f.tail + f.terminal)
	}))
	t.Cleanup(srv.Close)
	return srv, whole.String()
}

// streamTailRawUpstream serves body as the format's stream in pieces of
// piece bytes.
func streamTailRawUpstream(t *testing.T, f streamTailFormat, body string, piece int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", f.ctype)
		w.WriteHeader(http.StatusOK)
		fl := w.(http.Flusher)
		for i := 0; i < len(body); i += piece {
			_, _ = io.WriteString(w, body[i:min(i+piece, len(body))])
			fl.Flush()
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func streamTailProxy(t *testing.T, provider string, insp ContentInspector, mode string) *GuardrailProxy {
	t.Helper()
	orig := providerDomains
	providerDomains = append(append([]providerDomainEntry(nil), providerDomains...), providerDomainEntry{domain: "127.0.0.1", name: provider})
	t.Cleanup(func() { providerDomains = orig })
	return newTestProxy(t, &mockProvider{}, insp, mode)
}

func streamTailRequest(t *testing.T, f streamTailFormat, base, upstream string) *http.Request {
	t.Helper()
	body := mustJSON(t, map[string]any{"model": "m", "stream": true, "messages": []map[string]any{{"role": "user", "content": "hello"}}})
	req, err := http.NewRequest(http.MethodPost, base+f.path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DC-Target-URL", upstream)
	req.Header.Set("X-AI-Auth", "Bearer sk-test-upstream")
	req.RemoteAddr = "127.0.0.1:12345"
	return req
}

// streamTailTiers are the five tiers of the bound rule. The unknown tier
// follows the pack; a managed install with the default pack alerts.
var streamTailTiers = []struct {
	name, pack string
	managed    bool
	blocks     bool
}{
	{"default", "default", false, false},
	{"permissive", "permissive", false, false},
	{"strict", "strict", false, true},
	{"managed", "default", true, false},
	{"managed-strict", "strict", true, true},
}

// streamTailWithTier pins a generation whose config runs pack (on a managed
// install when managedInstall).
func streamTailWithTier(r *http.Request, pack string, managedInstall bool) *http.Request {
	cfg := &config.Config{}
	cfg.Guardrail.RulePack = pack
	if managedInstall {
		cfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
		cfg.Enterprise.Profile = managed.ProfileStandalone
	}
	return r.WithContext(withPinnedGeneration(r.Context(), &Generation{N: 1, Config: cfg}))
}

func streamTailServe(t *testing.T, proxy *GuardrailProxy, f streamTailFormat, upstream string) (string, string) {
	t.Helper()
	return streamTailServeReq(t, proxy, streamTailRequest(t, f, "", upstream))
}

func streamTailServeReq(t *testing.T, proxy *GuardrailProxy, req *http.Request) (string, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	log := captureStderr(t, func() { proxy.handlePassthrough(rec, req) })
	return rec.Body.String(), log
}

// streamTailReceivedText is the reply text a client reads from out. On an
// eventstream the block message the proxy ends a refused stream with is
// not reply text (streamTailUpstreamEvents).
func streamTailReceivedText(f streamTailFormat, out string) string {
	var sb strings.Builder
	if f.ctype == streamTailEventStream {
		for _, ev := range streamTailUpstreamEvents(out) {
			sb.WriteString(streamTailEventText("anthropic", ev))
		}
		return sb.String()
	}
	for _, line := range strings.Split(out, "\n") {
		if f.ctype == streamTailNDJSON {
			sb.WriteString(streamTailEventText(f.provider, strings.TrimSpace(line)))
			continue
		}
		if d, ok := strings.CutPrefix(strings.TrimSpace(line), "data: "); ok && d != "[DONE]" {
			sb.WriteString(streamTailEventText(f.provider, d))
		}
	}
	return sb.String()
}

// streamTailUpstreamEvents is the Anthropic events of the eventstream frames
// in out, without the block tail a refused Bedrock stream ends with
// (bedrockEventStreamText.writeBlockTail, streamTailWithoutBlockTail). A
// trailing partial frame is no event to the client.
func streamTailUpstreamEvents(out string) []string {
	var events []string
	dec, r := eventstream.NewDecoder(), strings.NewReader(out)
	for {
		msg, err := dec.Decode(r, nil)
		if err != nil {
			break
		}
		var chunk struct {
			Bytes []byte `json:"bytes"`
		}
		if json.Unmarshal(msg.Payload, &chunk) == nil {
			events = append(events, string(chunk.Bytes))
		}
	}
	return streamTailWithoutBlockTail(events)
}

// streamTailAnthropicSSEEvents is the data of the Anthropic Messages SSE
// events in out, without the block tail a refused stream ends with
// (writeAnthropicBlockTail, rel-1-0-10:GAP-1206).
func streamTailAnthropicSSEEvents(out string) []string {
	var events []string
	for _, line := range strings.Split(out, "\n") {
		if d, ok := strings.CutPrefix(strings.TrimSpace(line), "data: "); ok {
			events = append(events, d)
		}
	}
	return streamTailWithoutBlockTail(events)
}

// streamTailWithoutBlockTail is events, Anthropic Messages events, without
// the block tail the proxy ends a refused stream with: a text block opened
// after every block of the reply that carries the DefenseClaw block message,
// then message_delta and message_stop.
func streamTailWithoutBlockTail(events []string) []string {
	type ev struct {
		Type         string `json:"type"`
		Index        *int   `json:"index"`
		ContentBlock struct {
			Type string `json:"type"`
		} `json:"content_block"`
	}
	read := func(s string) ev {
		var e ev
		_ = json.Unmarshal([]byte(s), &e)
		return e
	}
	n := len(events)
	if n < 5 {
		return events
	}
	start := read(events[n-5])
	if start.Type != "content_block_start" || start.ContentBlock.Type != "text" || start.Index == nil ||
		!strings.HasPrefix(streamTailEventText("anthropic", events[n-4]), "[DefenseClaw] ") ||
		read(events[n-2]).Type != "message_delta" || read(events[n-1]).Type != "message_stop" {
		return events
	}
	for _, e := range events[:n-5] {
		if i := read(e).Index; i != nil && *i >= *start.Index {
			return events
		}
	}
	return events[:n-5]
}

// streamTailSentTerminal reports that the upstream's terminal event reached
// the client: on an eventstream, and in an Anthropic Messages SSE stream, a
// message_stop event that is not part of the proxy's block tail (GAP-1206:
// the tail ends the message as the API does).
func streamTailSentTerminal(f streamTailFormat, out string) bool {
	var events []string
	switch {
	case f.ctype == streamTailEventStream:
		events = streamTailUpstreamEvents(out)
	case f.provider == "anthropic" && f.ctype == streamTailSSE:
		events = streamTailAnthropicSSEEvents(out)
	default:
		return strings.Contains(out, f.terminal)
	}
	for _, e := range events {
		var ev struct {
			Type string `json:"type"`
		}
		if json.Unmarshal([]byte(e), &ev) == nil && ev.Type == "message_stop" {
			return true
		}
	}
	return false
}

// streamTailEventText is the text of one event of the test formats (read
// here, not with the product extractor, so the tests stay independent of
// it): an Anthropic text delta, a Responses output_text delta, Gemini parts,
// an Ollama message.
func streamTailEventText(provider, data string) string {
	var ev struct {
		Type    string          `json:"type"`
		Delta   json.RawMessage `json:"delta"`
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		Cands []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if json.Unmarshal([]byte(data), &ev) != nil {
		return ""
	}
	var sb strings.Builder
	switch provider {
	case "anthropic":
		var d struct {
			Text string `json:"text"`
		}
		if ev.Type == "content_block_delta" && json.Unmarshal(ev.Delta, &d) == nil {
			sb.WriteString(d.Text)
		}
	case "openai":
		var d string
		if ev.Type == "response.output_text.delta" && json.Unmarshal(ev.Delta, &d) == nil {
			sb.WriteString(d)
		}
	case "ollama":
		sb.WriteString(ev.Message.Content)
	case "gemini":
		for _, c := range ev.Cands {
			for _, p := range c.Content.Parts {
				sb.WriteString(p.Text)
			}
		}
	}
	return sb.String()
}

// streamTailAtomicEnd makes the upstream reply from the first occurrence of
// end onward reach the proxy as one read that also returns io.EOF, so no
// hold tick can fall between the last delta and the end of the stream
// (rel-1-0-10:GAP-0626: on a slow host a 100 ms tick released the last
// delta after the stub's mid-stream check allowed it, before the final
// check, and the test read that as a leak).
func streamTailAtomicEnd(t *testing.T, end string) {
	t.Helper()
	orig := providerHTTPClient
	c := *orig
	base := c.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	c.Transport = streamTailEndTransport{base: base, end: end}
	providerHTTPClient = &c
	t.Cleanup(func() { providerHTTPClient = orig })
}

type streamTailEndTransport struct {
	base http.RoundTripper
	end  string
}

func (rt streamTailEndTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := rt.base.RoundTrip(req)
	if err != nil {
		return resp, err
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	cut := bytes.Index(body, []byte(rt.end))
	if cut < 0 {
		cut = len(body)
	}
	resp.Body = &streamTailEndBody{head: body[:cut], end: body[cut:]}
	resp.ContentLength = -1
	return resp, nil
}

// streamTailEndBody reads head in pieces, then end in one read with io.EOF.
type streamTailEndBody struct{ head, end []byte }

func (b *streamTailEndBody) Read(p []byte) (int, error) {
	if len(b.head) > 0 {
		n := copy(p, b.head[:min(len(b.head), 512)])
		b.head = b.head[n:]
		return n, nil
	}
	if len(b.end) > len(p) {
		return 0, fmt.Errorf("stream end of %d bytes does not fit one %d-byte read", len(b.end), len(p))
	}
	n := copy(p, b.end)
	b.end = nil
	return n, io.EOF
}

func (b *streamTailEndBody) Close() error { return nil }

// The final check covers the tail and is enforced: the marker in the last
// delta (after the last 500-byte scan) is never sent and the stream ends
// without its terminal event, as a mid-stream block ends it. The last
// delta arrives with the end of the stream, so the case does not depend on
// the clock (GAP-0626).
func TestStreamTailFinalCheckWithholdsTail(t *testing.T) {
	last := "and then " + streamTailMarker + " ends"
	for _, f := range streamTailFormats {
		for _, mid := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/mid=%v", f.name, mid), func(t *testing.T) {
				insp := &streamTailInspector{mockInspector: newMockInspector(), final: true, mid: mid}
				up, _ := streamTailUpstream(t, f, streamTailDeltas(2400, 24, last), 0, nil)
				streamTailAtomicEnd(t, f.delta(last))
				proxy := streamTailProxy(t, f.provider, insp, "action")
				out, log := streamTailServe(t, proxy, f, up.URL)
				if strings.Contains(streamTailReceivedText(f, out), streamTailMarker) || strings.Contains(out, f.delta(last)) {
					t.Fatalf("the tail marker reached the client")
				}
				if streamTailSentTerminal(f, out) {
					t.Fatalf("a blocked stream ended with its terminal event")
				}
				if !strings.Contains(out, f.delta(streamTailDeltas(2400, 24)[0])) {
					t.Fatalf("the checked head of the stream was not sent: %d bytes", len(out))
				}
				if !strings.Contains(log, "PASSTHROUGH-STREAM-BLOCK") {
					t.Fatalf("no block line: %s", log)
				}
			})
		}
	}
}

// A clean stream reaches the client byte for byte, in action mode as in
// observe mode; in observe mode a finding changes nothing (it is recorded
// as a would-block).
func TestStreamTailCleanAndObserveStreamsUnchanged(t *testing.T) {
	for _, f := range streamTailFormats {
		for _, tc := range []struct {
			name, mode string
			deltas     []string
		}{
			{"clean/action", "action", streamTailDeltas(2400, 24)},
			{"clean/observe", "observe", streamTailDeltas(2400, 24)},
			{"finding/observe", "observe", streamTailDeltas(2400, 24, streamTailMarker)},
			{"short/action", "action", streamTailDeltas(300, 24)},
		} {
			t.Run(f.name+"/"+tc.name, func(t *testing.T) {
				insp := &streamTailInspector{mockInspector: newMockInspector(), final: true, mid: true}
				up, whole := streamTailUpstream(t, f, tc.deltas, 0, nil)
				proxy := streamTailProxy(t, f.provider, insp, tc.mode)
				out, log := streamTailServe(t, proxy, f, up.URL)
				if out != whole {
					t.Fatalf("stream changed: got %d bytes, want %d", len(out), len(whole))
				}
				if strings.Contains(tc.name, "finding") && !strings.Contains(log, "PASSTHROUGH-STREAM-VIOLATION") {
					t.Fatalf("observe-mode finding not recorded: %s", log)
				}
				if insp.finals != 1 {
					t.Fatalf("final checks = %d, want 1", insp.finals)
				}
			})
		}
	}
}

// A secret split across the last scan boundary is caught: the final check
// reads the whole text, so the marker whose first half went out with the
// 500-byte scan still ends the stream before its second half.
func TestStreamTailSplitAcrossLastScan(t *testing.T) {
	half := len(streamTailMarker) / 2
	for _, f := range streamTailFormats {
		t.Run(f.name, func(t *testing.T) {
			insp := &streamTailInspector{mockInspector: newMockInspector(), final: true, mid: true}
			// 1024 bytes fill the initial buffer; the next 500, the first half
			// of the marker included, trigger the last scan, which ends inside
			// the marker.
			prose := streamTailDeltas(1024+500-half, 1024+500-half)[0]
			deltas := []string{prose[:1024], prose[1024:], streamTailMarker[:half], streamTailMarker[half:], " and more words"}
			// A gap between deltas keeps each in its own read.
			up, _ := streamTailUpstream(t, f, deltas, 30*time.Millisecond, nil)
			proxy := streamTailProxy(t, f.provider, insp, "action")
			out, _ := streamTailServe(t, proxy, f, up.URL)
			if !strings.Contains(out, f.delta(streamTailMarker[:half])) {
				t.Fatalf("the last scan did not end inside the marker (setup)")
			}
			if strings.Contains(out, f.delta(streamTailMarker[half:])) || streamTailSentTerminal(f, out) {
				t.Fatalf("the second half of a split marker or the terminal event was sent")
			}
		})
	}
}

// An upstream that never sends its final event and stays open: every held
// byte is checked and sent within the hold's time bound; a finding in it is
// still checked and ends the stream. Nothing waits for the connection.
func TestStreamTailIdleUpstreamIsBounded(t *testing.T) {
	for _, f := range streamTailFormats {
		for _, finding := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/finding=%v", f.name, finding), func(t *testing.T) {
				stall := make(chan struct{})
				defer close(stall)
				deltas := streamTailDeltas(1500, 24, "closing words here")
				if finding {
					deltas = append(deltas, streamTailMarker)
				}
				insp := &streamTailInspector{mockInspector: newMockInspector(), mid: true, final: true}
				up, _ := streamTailUpstream(t, f, deltas, 0, stall)
				proxy := streamTailProxy(t, f.provider, insp, "action")
				front := httptest.NewServer(http.HandlerFunc(proxy.handlePassthrough))
				defer front.Close()
				resp, err := http.DefaultClient.Do(streamTailRequest(t, f, front.URL, up.URL))
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				last := f.delta(deltas[len(deltas)-1])
				got := make(chan string, 1)
				go func() {
					var sb strings.Builder
					rd := bufio.NewReader(resp.Body)
					buf := make([]byte, 4096)
					for {
						n, err := rd.Read(buf)
						sb.Write(buf[:n])
						if (!finding && strings.Contains(sb.String(), last)) || err != nil {
							got <- sb.String()
							return
						}
					}
				}()
				bound := streamHoldMaxAge + 2*time.Second
				select {
				case out := <-got:
					if finding && strings.Contains(out, streamTailMarker) {
						t.Fatal("the held marker reached the client")
					}
				case <-time.After(bound):
					t.Fatalf("held bytes not sent (or the stream not ended) within %v of an idle upstream", bound)
				}
			})
		}
	}
}

// The /llm route (handleChatCompletion through a provider adapter): the
// final check is enforced on the tail, observe mode changes nothing, and an
// idle provider stream does not hold the tail.
func TestStreamTailLLMRoute(t *testing.T) {
	text := func(chunks []string) []StreamChunk {
		var out []StreamChunk
		for _, c := range chunks {
			out = append(out, StreamChunk{ID: "c1", Object: "chat.completion.chunk", Model: "gpt-4",
				Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{Content: c}}}})
		}
		stop := "stop"
		return append(out, StreamChunk{ID: "c1", Object: "chat.completion.chunk", Model: "gpt-4",
			Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{}, FinishReason: &stop}}})
	}
	body := mustJSON(t, map[string]any{"model": "gpt-4", "stream": true, "messages": []map[string]any{{"role": "user", "content": "hello"}}})
	for _, tc := range []struct {
		name, mode string
		marker     bool
	}{{"finding/action", "action", true}, {"finding/observe", "observe", true}, {"clean/action", "action", false}} {
		t.Run(tc.name, func(t *testing.T) {
			chunks := streamTailDeltas(2400, 24)
			if tc.marker {
				chunks = append(chunks, "and "+streamTailMarker)
			}
			prov := &mockProvider{streamChunks: text(chunks)}
			insp := &streamTailInspector{mockInspector: newMockInspector(), final: true}
			proxy := newTestProxy(t, prov, insp, tc.mode)
			rec := postChat(t, proxy, body)
			out := rec.Body.String()
			blocked := tc.marker && tc.mode == "action"
			if tc.marker && blocked == strings.Contains(out, streamTailMarker) {
				t.Fatalf("marker sent=%v, want blocked=%v", strings.Contains(out, streamTailMarker), blocked)
			}
			if blocked && !strings.Contains(out, "content blocked mid-stream by guardrail") {
				t.Fatalf("no block chunk")
			}
			if !strings.HasSuffix(out, "data: [DONE]\n\n") {
				t.Fatalf("stream not terminated")
			}
			if !blocked && !strings.Contains(out, `"finish_reason":"stop"`) {
				t.Fatalf("finish chunk missing")
			}
		})
	}
	t.Run("idle", func(t *testing.T) {
		stall := make(chan struct{})
		defer close(stall)
		prov := &streamTailStallProvider{chunks: text(streamTailDeltas(1500, 24))[:63], stall: stall}
		insp := &streamTailInspector{mockInspector: newMockInspector(), final: true, mid: true}
		proxy := newTestProxy(t, prov, insp, "action")
		front := httptest.NewServer(http.HandlerFunc(proxy.handleChatCompletion))
		defer front.Close()
		req, _ := http.NewRequest(http.MethodPost, front.URL+"/v1/chat/completions", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		last := prov.chunks[len(prov.chunks)-1].Choices[0].Delta.Content
		got := make(chan bool, 1)
		go func() {
			var sb strings.Builder
			buf := make([]byte, 4096)
			for {
				n, err := resp.Body.Read(buf)
				sb.Write(buf[:n])
				if strings.Count(sb.String(), `"content":`) >= len(prov.chunks) && strings.Contains(sb.String(), last) {
					got <- true
					return
				}
				if err != nil {
					got <- false
					return
				}
			}
		}()
		select {
		case ok := <-got:
			if !ok {
				t.Fatal("stream ended before the held chunks arrived")
			}
		case <-time.After(streamHoldMaxAge + 2*time.Second):
			t.Fatal("held chunks not sent within the bound while the provider is idle")
		}
	})
}

// streamTailStallProvider sends its chunks and then stays open, idle,
// until stall closes or the request ends.
type streamTailStallProvider struct {
	mockProvider
	chunks []StreamChunk
	stall  <-chan struct{}
}

func (s *streamTailStallProvider) ChatCompletionStream(ctx context.Context, _ *ChatRequest, cb func(StreamChunk)) (*ChatUsage, error) {
	for _, c := range s.chunks {
		cb(c)
	}
	select {
	case <-s.stall:
	case <-ctx.Done():
	}
	return &ChatUsage{}, nil
}

// streamTailImage is a benign base64 image of about 1.6 MB.
func streamTailImage() string {
	raw := make([]byte, 1200<<10)
	mrand.New(mrand.NewSource(7)).Read(raw)
	return base64.StdEncoding.EncodeToString(raw)
}

// The text bound of a held line applies to the text the check reads, not to
// the raw bytes (rel-1-0-10:GAP-0624). A benign line of about 1.6 MB that
// carries an image result (Responses image_generation_call, Gemini
// inlineData) and little text is read whole once it ends and passes in
// every tier, byte for byte, with no alert. A line whose text is over
// streamLineMaxText is TRUNCATED (bound rule): its text is checked, then
// the default, permissive and managed tiers alert and send it, and the
// strict tiers block it before any of it is sent. A line just under the
// text bound passes.
func TestStreamTailBigLine(t *testing.T) {
	img := streamTailImage()
	if len(img) <= 1<<20 {
		t.Fatalf("image of %d bytes is not over 1 MiB (setup)", len(img))
	}
	responses := streamTailFormatNamed(t, "openai-responses")
	gemini := streamTailFormatNamed(t, "gemini")
	images := []struct {
		name string
		f    streamTailFormat
		line string
	}{
		{"responses/image_generation_call", responses, "event: response.output_item.done\ndata: " + streamTailJSON(map[string]any{
			"type": "response.output_item.done", "output_index": 1,
			"item": map[string]any{"type": "image_generation_call", "id": "ig_1", "status": "completed", "result": img},
		}) + "\n\n"},
		{"responses/partial_image", responses, "event: response.image_generation_call.partial_image\ndata: " + streamTailJSON(map[string]any{
			"type": "response.image_generation_call.partial_image", "item_id": "ig_1", "partial_image_index": 0, "partial_image_b64": img,
		}) + "\n\n"},
		{"gemini/inlineData", gemini, streamTailGeminiEvent(0, []any{
			map[string]any{"text": "here is the picture"},
			map[string]any{"inlineData": map[string]any{"mimeType": "image/png", "data": img}},
		}, nil)},
	}
	for _, im := range images {
		for _, tier := range streamTailTiers {
			t.Run("benign/"+im.name+"/"+tier.name, func(t *testing.T) {
				f := im.f
				body := f.head + f.delta(streamTailProse(1440)) + im.line + f.delta(streamTailProse(700)) + f.tail + f.terminal
				up := streamTailRawUpstream(t, f, body, 32<<10)
				insp := &streamTailInspector{mockInspector: newMockInspector(), final: true, mid: true}
				proxy := streamTailProxy(t, f.provider, insp, "action")
				out, log := streamTailServeReq(t, proxy, streamTailWithTier(streamTailRequest(t, f, "", up.URL), tier.pack, tier.managed))
				if out != body {
					t.Fatalf("a benign image line changed the stream: got %d bytes, want %d", len(out), len(body))
				}
				if strings.Contains(log, "PASSTHROUGH-STREAM-TRUNCATED") || strings.Contains(log, "PASSTHROUGH-STREAM-BLOCK") {
					t.Fatalf("a benign image line alerted or blocked: %s", log)
				}
			})
		}
	}

	over := streamTailProse(streamLineMaxText + 100)
	under := streamTailProse(streamLineMaxText - 4096)
	for _, f := range streamTailFormats {
		tiers := streamTailTiers
		if f.name != "anthropic" {
			tiers = []struct {
				name, pack string
				managed    bool
				blocks     bool
			}{streamTailTiers[0], streamTailTiers[2]}
		}
		for _, first := range []bool{false, true} {
			if first && f.name != "anthropic" {
				continue
			}
			lead := f.delta(streamTailProse(1440))
			if first {
				// The over-bound line is the first text: it ends while the
				// initial buffer still holds it.
				lead = ""
			}
			for _, tier := range tiers {
				t.Run(fmt.Sprintf("text-over-bound/%s/first=%v/%s", f.name, first, tier.name), func(t *testing.T) {
					body := f.head + lead + f.delta(over) + f.delta(streamTailProse(700)) + f.tail + f.terminal
					up := streamTailRawUpstream(t, f, body, 32<<10)
					insp := &streamTailInspector{mockInspector: newMockInspector(), final: true, mid: true}
					proxy := streamTailProxy(t, f.provider, insp, "action")
					out, log := streamTailServeReq(t, proxy, streamTailWithTier(streamTailRequest(t, f, "", up.URL), tier.pack, tier.managed))
					if tier.blocks {
						if strings.Contains(out, f.delta(over)) || streamTailSentTerminal(f, out) {
							t.Fatalf("the %s tier sent a line over the text bound: %d bytes", tier.name, len(out))
						}
						if !strings.Contains(log, "PASSTHROUGH-STREAM-BLOCK") {
							t.Fatalf("no block line: %s", log)
						}
						return
					}
					if out != body {
						t.Fatalf("the %s tier did not send the stream: got %d bytes, want %d", tier.name, len(out), len(body))
					}
					if !strings.Contains(log, "PASSTHROUGH-STREAM-TRUNCATED") {
						t.Fatalf("no truncation log line: %s", log)
					}
					alerts, err := proxy.store.ListAlerts(50)
					if err != nil {
						t.Fatal(err)
					}
					if !strings.Contains(fmt.Sprintf("%+v", alerts), "bounded_truncated cap=bytes") {
						t.Fatalf("no truncation alert row naming the cap: %+v", alerts)
					}
				})
			}
		}
		t.Run("text-under-bound/"+f.name+"/strict", func(t *testing.T) {
			body := f.head + f.delta(streamTailProse(1440)) + f.delta(under) + f.tail + f.terminal
			up := streamTailRawUpstream(t, f, body, 32<<10)
			insp := &streamTailInspector{mockInspector: newMockInspector(), final: true, mid: true}
			proxy := streamTailProxy(t, f.provider, insp, "action")
			out, log := streamTailServeReq(t, proxy, streamTailWithTier(streamTailRequest(t, f, "", up.URL), "strict", false))
			if out != body || strings.Contains(log, "PASSTHROUGH-STREAM-TRUNCATED") || strings.Contains(log, "PASSTHROUGH-STREAM-BLOCK") {
				t.Fatalf("a line under the text bound changed the stream (%d of %d bytes) or alerted: %s", len(out), len(body), log)
			}
		})
	}
}

// An SSE line that never ends within sseEventMax raw bytes is
// TRUNCATED (bound rule, cap bytes): the default pack alerts and sends it,
// the strict pack blocks it.
func TestStreamTailPartialLineBound(t *testing.T) {
	f := streamTailFormats[0] // an SSE passthrough format; an eventstream frame over the bound breaks framing first
	long := "data: " + strings.Repeat("x", sseEventMax+(64<<10))
	for _, strict := range []bool{false, true} {
		t.Run(fmt.Sprintf("strict=%v", strict), func(t *testing.T) {
			body := f.head + f.delta(streamTailProse(1440)) + long + "\n\n" + f.terminal
			up := streamTailRawUpstream(t, f, body, 32<<10)
			insp := &streamTailInspector{mockInspector: newMockInspector(), final: true, mid: true}
			proxy := streamTailProxy(t, f.provider, insp, "action")
			req := streamTailRequest(t, f, "", up.URL)
			if strict {
				req = streamTailWithTier(req, "strict", false)
			}
			out, log := streamTailServeReq(t, proxy, req)
			if strict {
				if strings.Contains(out, long[:sseEventMax]) || streamTailSentTerminal(f, out) {
					t.Fatalf("strict pack sent a truncated line: %d bytes", len(out))
				}
				if !strings.Contains(log, "PASSTHROUGH-STREAM-BLOCK") {
					t.Fatalf("no block line: %s", log)
				}
				return
			}
			if out != body {
				t.Fatalf("default pack did not send the stream: got %d bytes, want %d", len(out), len(body))
			}
			if !strings.Contains(log, "PASSTHROUGH-STREAM-TRUNCATED") {
				t.Fatalf("no truncation log line")
			}
			// The reason is redacted in the log; the telemetry row names the cap.
			alerts, err := proxy.store.ListAlerts(50)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(fmt.Sprintf("%+v", alerts), "bounded_truncated cap=bytes") {
				t.Fatalf("no truncation alert row naming the cap: %+v", alerts)
			}
		})
	}
}

// An upstream that stops inside a line or frame and stays open:
// streamHoldMaxPartialAge after its last byte the stream is TRUNCATED (bound
// rule, cap time): the strict pack ends the stream; the default pack alerts
// and keeps the unfinished line held (GAP-0316). Every passthrough format.
func TestStreamTailStalledPartialLine(t *testing.T) {
	for _, f := range streamTailFormats {
		for _, strict := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/strict=%v", f.name, strict), func(t *testing.T) {
				unfinished := f.delta("an unfinished delta of plain words")
				// The part of the event the upstream sends before it stalls:
				// up to the middle of its text where the event carries the text as is
				// (every NDJSON line of the format starts with the same 58
				// bytes, so half a line is no mark of this one, GAP-0322),
				// else half the event (a Bedrock frame carries it in base64).
				partial := unfinished[:len(unfinished)/2]
				if i := strings.Index(unfinished, "unfinished delta"); i >= 0 {
					partial = unfinished[:i+len("unfinished")]
				}
				stall := make(chan struct{})
				defer close(stall)
				up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", f.ctype)
					fl := w.(http.Flusher)
					_, _ = io.WriteString(w, f.head+f.delta(strings.Repeat("plain words ", 120)))
					fl.Flush()
					time.Sleep(20 * time.Millisecond)
					_, _ = io.WriteString(w, partial)
					fl.Flush()
					select {
					case <-stall:
					case <-r.Context().Done():
					}
				}))
				defer up.Close()
				insp := &streamTailInspector{mockInspector: newMockInspector(), final: true, mid: true}
				proxy := streamTailProxy(t, f.provider, insp, "action")
				front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if strict {
						r = streamTailWithTier(r, "strict", false)
					}
					proxy.handlePassthrough(w, r)
				}))
				defer front.Close()
				resp, err := http.DefaultClient.Do(streamTailRequest(t, f, front.URL, up.URL))
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				got := make(chan string, 1)
				go func() {
					var sb strings.Builder
					buf := make([]byte, 4096)
					for {
						n, err := resp.Body.Read(buf)
						sb.Write(buf[:n])
						if strings.Contains(sb.String(), partial) || err != nil {
							got <- sb.String()
							return
						}
					}
				}()
				if !strict {
					// GAP-0316 (the tool-call hold outranks the tail timers):
					// the default pack records the TRUNCATED alert and keeps
					// the unfinished event held, since its unread bytes may
					// start a tool call. The stream stays open. The alert is
					// read from its telemetry row: os.Stderr cannot be
					// swapped while the handler runs (a data race).
					time.Sleep(streamHoldMaxPartialAge + 1500*time.Millisecond)
					select {
					case out := <-got:
						t.Fatalf("the default pack sent the unfinished line or ended the stream (%d bytes)", len(out))
					default:
					}
					alerts, err := proxy.store.ListAlerts(50)
					if err != nil {
						t.Fatal(err)
					}
					if !strings.Contains(fmt.Sprintf("%+v", alerts), "bounded_truncated cap=time") {
						t.Fatalf("no truncation alert row naming the cap: %+v", alerts)
					}
					return
				}
				select {
				case out := <-got:
					if strict && strings.Contains(out, partial) {
						t.Fatal("the strict pack sent an unfinished line past the bound")
					}
				case <-time.After(streamHoldMaxPartialAge + 3*time.Second):
					t.Fatalf("the unfinished line was held past %v", streamHoldMaxPartialAge)
				}
			})
		}
	}
}

// A long line that the upstream sends slowly but steadily is held while it
// arrives, past streamHoldMaxPartialAge in total, and passes whole: the time
// bound counts from the last byte (GAP-0624, a large image on a slow link).
func TestStreamTailSlowLongLineIsNotTruncated(t *testing.T) {
	f := streamTailFormatNamed(t, "gemini")
	line := streamTailGeminiEvent(0, []any{map[string]any{"inlineData": map[string]any{"mimeType": "image/png", "data": streamTailImage()[:256<<10]}}}, nil)
	const pieces = 3
	gap := streamHoldMaxPartialAge/2 + 200*time.Millisecond // total > streamHoldMaxPartialAge
	head := f.head + f.delta(streamTailProse(1440))
	body := head + line + f.delta(streamTailProse(300)) + f.tail + f.terminal
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", f.ctype)
		fl := w.(http.Flusher)
		_, _ = io.WriteString(w, head)
		fl.Flush()
		step := len(line)/pieces + 1
		for i := 0; i < len(line); i += step {
			_, _ = io.WriteString(w, line[i:min(i+step, len(line))])
			fl.Flush()
			if i+step < len(line) {
				select {
				case <-time.After(gap):
				case <-r.Context().Done():
					return
				}
			}
		}
		_, _ = io.WriteString(w, body[len(head)+len(line):])
	}))
	defer up.Close()
	insp := &streamTailInspector{mockInspector: newMockInspector(), final: true, mid: true}
	proxy := streamTailProxy(t, f.provider, insp, "action")
	out, log := streamTailServeReq(t, proxy, streamTailWithTier(streamTailRequest(t, f, "", up.URL), "strict", false))
	if out != body {
		t.Fatalf("a slow benign line changed the stream: got %d bytes, want %d", len(out), len(body))
	}
	if strings.Contains(log, "PASSTHROUGH-STREAM-TRUNCATED") || strings.Contains(log, "PASSTHROUGH-STREAM-BLOCK") {
		t.Fatalf("a slow benign line alerted or blocked: %s", log)
	}
}
