// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Rows of the 1.0.10 stream fixes of train T-OBS: the initial buffer has
// the hold's time bound (rel-1-0-10:GAP-0628), a check due by age only is
// the local one (GAP-0625), and the reply extractor reads the revised
// prompt of an image call and text-typed inline data (GAP-0687). Whatever
// reaches the client was checked first; a finding still ends the stream.

// obsStreamClient reads a streamed reply as it arrives.
type obsStreamClient struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	ended bool
}

// obsStreamStart sends req and fails the test when the reply headers do not
// arrive within headerBound. Cleanups close the reply first, then the
// servers the caller registered before, so an idle upstream ends with it.
func obsStreamStart(t *testing.T, req *http.Request, headerBound time.Duration) *obsStreamClient {
	t.Helper()
	type result struct {
		resp *http.Response
		err  error
	}
	// Cancelled first of the cleanups: a reply that never came still ends
	// the proxy's request, so the servers can close.
	ctx, cancel := context.WithCancel(req.Context())
	t.Cleanup(cancel)
	req = req.WithContext(ctx)
	ch := make(chan result, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		ch <- result{resp, err}
	}()
	var resp *http.Response
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatal(r.err)
		}
		resp = r.resp
	case <-time.After(headerBound):
		t.Fatalf("no reply headers within %v", headerBound)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	c := &obsStreamClient{}
	go func() {
		b := make([]byte, 4096)
		for {
			n, err := resp.Body.Read(b)
			c.mu.Lock()
			c.buf.Write(b[:n])
			if err != nil {
				c.ended = true
			}
			c.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	return c
}

// waitFor polls the reply until cond holds or bound passes; ok reports cond.
func (c *obsStreamClient) waitFor(bound time.Duration, cond func(body string, ended bool) bool) (string, bool) {
	deadline := time.Now().Add(bound)
	for {
		c.mu.Lock()
		body, ended := c.buf.String(), c.ended
		c.mu.Unlock()
		if cond(body, ended) {
			return body, true
		}
		if ended || time.Now().After(deadline) {
			return body, false
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// obsIdleUpstream is the passthrough front and an upstream that sends
// deltas (gap apart) and then stays open, idle, until the test ends.
func obsIdleUpstream(t *testing.T, f streamTailFormat, insp ContentInspector, deltas []string, gap time.Duration) *http.Request {
	t.Helper()
	stall := make(chan struct{})
	t.Cleanup(func() { close(stall) })
	up, _ := streamTailUpstream(t, f, deltas, gap, stall)
	proxy := streamTailProxy(t, f.provider, insp, "action")
	front := httptest.NewServer(http.HandlerFunc(proxy.handlePassthrough))
	t.Cleanup(front.Close)
	return streamTailRequest(t, f, front.URL, up.URL)
}

// obsPacedStallProvider sends its chunks gap apart, then stays open, idle,
// until stall closes or the request ends.
type obsPacedStallProvider struct {
	mockProvider
	chunks []string
	gap    time.Duration
	stall  <-chan struct{}
}

func (s *obsPacedStallProvider) ChatCompletionStream(ctx context.Context, _ *ChatRequest, cb func(StreamChunk)) (*ChatUsage, error) {
	for _, c := range s.chunks {
		if s.gap > 0 {
			select {
			case <-time.After(s.gap):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		cb(StreamChunk{ID: "c1", Object: "chat.completion.chunk", Model: "gpt-4", Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{Content: c}}}})
	}
	select {
	case <-s.stall:
	case <-ctx.Done():
	}
	return &ChatUsage{}, nil
}

// obsIdleLLM is the /llm front over a provider that sends chunks (gap
// apart) and then stays open, idle, until the test ends.
func obsIdleLLM(t *testing.T, insp ContentInspector, chunks []string, gap time.Duration) *http.Request {
	t.Helper()
	stall := make(chan struct{})
	t.Cleanup(func() { close(stall) })
	proxy := newTestProxy(t, &obsPacedStallProvider{chunks: chunks, gap: gap, stall: stall}, insp, "action")
	front := httptest.NewServer(http.HandlerFunc(proxy.handleChatCompletion))
	t.Cleanup(front.Close)
	body := mustJSON(t, map[string]any{"model": "gpt-4", "stream": true, "messages": []map[string]any{{"role": "user", "content": "hello"}}})
	req, err := http.NewRequest(http.MethodPost, front.URL+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	return req
}

// The initial buffer is bounded in time (rel-1-0-10:GAP-0628): a reply
// shorter than stream_buffer_bytes from an upstream that then goes idle
// reaches the client (headers at once, text once the upstream was quiet for
// streamHoldMaxAge) after a check has read it. A finding in it, or one that
// arrives after the first text went out, still ends the stream and never
// reaches the client; a stream that keeps coming keeps the pre-block (none
// of its text is sent before the finding ends it). All passthrough formats
// and /llm.
func TestGAP0628InitialBufferIsTimeBounded(t *testing.T) {
	bound := streamHoldMaxAge + 2*time.Second
	short := streamTailDeltas(300, 24, "closing words here")
	cases := []struct {
		name    string
		deltas  []string
		gap     time.Duration
		finding bool
	}{
		{"short-clean", short, 0, false},
		{"short-finding", append(append([]string(nil), short...), "and "+streamTailMarker), 0, true},
		{"finding-after-first-text", []string{streamTailProse(120), " more words here ", " and " + streamTailMarker}, 250 * time.Millisecond, true},
		{"continuous-finding", append(append([]string(nil), short...), "and "+streamTailMarker), 5 * time.Millisecond, true},
	}
	// sentEarly reports whether the case's first text is released before
	// the finding ends the stream: only when the upstream paused first.
	sentEarly := func(gap time.Duration) bool { return gap > streamHoldMaxAge }
	for _, f := range streamTailFormats {
		for _, tc := range cases {
			t.Run(f.name+"/"+tc.name, func(t *testing.T) {
				insp := &obsFinalInspector{&streamTailInspector{mockInspector: newMockInspector(), mid: true, final: true}, true}
				c := obsStreamStart(t, obsIdleUpstream(t, f, insp, tc.deltas, tc.gap), bound)
				if !tc.finding {
					last := f.delta(tc.deltas[len(tc.deltas)-1])
					body, ok := c.waitFor(bound, func(body string, _ bool) bool { return strings.Contains(body, last) })
					if !ok {
						t.Fatalf("the short reply did not reach the client within %v of an idle upstream (%d bytes got)", bound, len(body))
					}
					if got := streamTailReceivedText(f, body); !strings.Contains(got, "closing words here") {
						t.Fatalf("reply text %q", got)
					}
					return
				}
				body, ok := c.waitFor(bound, func(_ string, ended bool) bool { return ended })
				if !ok {
					t.Fatalf("a finding in the initial buffer did not end the stream within %v of an idle upstream (%d bytes got)", bound, len(body))
				}
				if strings.Contains(streamTailReceivedText(f, body), streamTailMarker) || strings.Contains(body, streamTailMarker) {
					t.Fatal("the marker reached the client")
				}
				if streamTailSentTerminal(f, body) {
					t.Fatal("a refused stream ended as a finished reply")
				}
				if got := streamTailReceivedText(f, body); sentEarly(tc.gap) != strings.Contains(got, streamTailProse(100)) {
					t.Fatalf("first text sent before the block: %v, want %v (reply text %q)", !sentEarly(tc.gap), sentEarly(tc.gap), got)
				}
			})
		}
	}
	for _, tc := range cases {
		t.Run("llm/"+tc.name, func(t *testing.T) {
			insp := &obsFinalInspector{&streamTailInspector{mockInspector: newMockInspector(), mid: true, final: true}, true}
			c := obsStreamStart(t, obsIdleLLM(t, insp, tc.deltas, tc.gap), bound)
			if !tc.finding {
				body, ok := c.waitFor(bound, func(body string, _ bool) bool { return strings.Contains(body, "closing words here") })
				if !ok {
					t.Fatalf("the short reply did not reach the client within %v of an idle provider (%d bytes got)", bound, len(body))
				}
				return
			}
			body, ok := c.waitFor(bound, func(_ string, ended bool) bool { return ended })
			if !ok {
				t.Fatalf("a finding in the initial buffer did not end the stream within %v of an idle provider (%d bytes got)", bound, len(body))
			}
			if strings.Contains(body, streamTailMarker) || !strings.Contains(body, "content blocked mid-stream by guardrail") {
				t.Fatalf("marker sent=%v, block chunk=%v", strings.Contains(body, streamTailMarker), strings.Contains(body, "content blocked mid-stream by guardrail"))
			}
			if sentEarly(tc.gap) != strings.Contains(streamTailLLMText(body), streamTailProse(100)) {
				t.Fatalf("first text sent before the block: %v, want %v", !sentEarly(tc.gap), sentEarly(tc.gap))
			}
		})
	}
}

// When the mid-stream check does not decide as the final one (a managed
// install, a judge strategy: MidStreamDecidesAsFinal false), the headers
// still go out at once but the initial buffer waits for the end of the
// stream, as before: the final check may refuse the whole reply
// (rel-1-0-10:GAP-0628).
func TestGAP0628InitialBufferWaitsWhenTheFinalCheckDecides(t *testing.T) {
	bound := streamHoldMaxAge + 2*time.Second
	short := streamTailDeltas(300, 24, "closing words here")
	wait := func(t *testing.T, c *obsStreamClient) {
		t.Helper()
		if body, ok := c.waitFor(5*streamHoldMaxAge, func(body string, ended bool) bool {
			return ended || strings.Contains(body, "closing words here") || strings.Contains(streamTailReceivedText(streamTailFormatNamed(t, "anthropic"), body), "closing")
		}); ok {
			t.Fatalf("the initial buffer went out before the final check (%d bytes)", len(body))
		}
	}
	t.Run("anthropic", func(t *testing.T) {
		f := streamTailFormatNamed(t, "anthropic")
		insp := &obsFinalInspector{&streamTailInspector{mockInspector: newMockInspector(), mid: true, final: true}, false}
		wait(t, obsStreamStart(t, obsIdleUpstream(t, f, insp, short, 0), bound))
	})
	t.Run("llm", func(t *testing.T) {
		insp := &obsFinalInspector{&streamTailInspector{mockInspector: newMockInspector(), mid: true, final: true}, false}
		wait(t, obsStreamStart(t, obsIdleLLM(t, insp, short, 0), bound))
	})
}

// obsFinalInspector says whether its mid-stream check decides as its final
// check (midStreamFinalInspector).
type obsFinalInspector struct {
	*streamTailInspector
	asFinal bool
}

func (i *obsFinalInspector) MidStreamDecidesAsFinal() bool { return i.asFinal }

// obsCountingAID is an AI Defense client that counts its calls and flags a
// message that carries marker (when set).
type obsCountingAID struct {
	calls  atomic.Int64
	marker string
}

func (a *obsCountingAID) Inspect(_ context.Context, messages []ChatMessage) *ScanVerdict {
	a.calls.Add(1)
	for _, m := range messages {
		if a.marker != "" && strings.Contains(m.Content, a.marker) {
			return &ScanVerdict{Action: "block", Severity: "CRITICAL", Reason: "aid marker", Findings: []string{"test:aid-marker"}, Scanner: "ai-defense"}
		}
	}
	return &ScanVerdict{Action: "allow", Severity: "NONE", Scanner: "ai-defense"}
}

func (a *obsCountingAID) bindObservabilityV8(hookLifecycleMetricV8Runtime) {}

// obsBothInspector is the gateway's inspector with scanner_mode both over
// aid; spans counts the completion checks that open an evaluation span.
func obsBothInspector(aid *obsCountingAID) (*GuardrailInspector, *atomic.Int64) {
	g := NewGuardrailInspector("both", nil, nil)
	g.SetCiscoInspector(aid)
	spans := &atomic.Int64{}
	g.SetTracerFunc(func(ctx context.Context, _, direction, _, _ string) (context.Context, func(*ScanVerdict, time.Duration)) {
		if direction == "completion" {
			spans.Add(1)
		}
		return ctx, func(*ScanVerdict, time.Duration) {}
	})
	return g, spans
}

// A check of the stream hold that is due by age only is the local one
// (rel-1-0-10:GAP-0625): on a slow stream (8 bytes every 10 ms) with
// scanner_mode both, AI Defense is asked, and an evaluation span opened,
// about once per 500 bytes of text as before the hold, not every 100 ms;
// the hold still lets every byte out without the final event (the upstream
// is idle after the last delta). A finding only AI Defense makes still ends
// the stream (at the next full check), never as a finished reply.
func TestGAP0625AgeDueChecksStayLocal(t *testing.T) {
	const n, size, gap = 250, 8, 10 * time.Millisecond
	// The last delta is unique: the prose repeats every 64 bytes.
	deltas := streamTailDeltas(n*size, size, "closing words zq-0625-end")
	// The initial buffer, then one full check per 500 bytes, with slack.
	maxFull := int64(n*size/500 + 3)
	bound := time.Duration(n)*gap*3 + streamHoldMaxAge + 3*time.Second
	f := streamTailFormatNamed(t, "anthropic")
	check := func(t *testing.T, aid *obsCountingAID, spans *atomic.Int64) {
		t.Helper()
		calls, opened := aid.calls.Load(), spans.Load()
		t.Logf("%d bytes of text: AI Defense calls %d, evaluation spans %d (max %d)", n*size, calls, opened, maxFull)
		if calls == 0 || calls > maxFull || opened > maxFull {
			t.Fatalf("AI Defense calls %d, evaluation spans %d over %d bytes of text: want 1..%d", calls, opened, n*size, maxFull)
		}
	}
	t.Run("passthrough", func(t *testing.T) {
		aid := &obsCountingAID{}
		insp, spans := obsBothInspector(aid)
		c := obsStreamStart(t, obsIdleUpstream(t, f, insp, deltas, gap), bound)
		last := f.delta(deltas[len(deltas)-1])
		if body, ok := c.waitFor(bound, func(body string, _ bool) bool { return strings.Contains(body, last) }); !ok {
			t.Fatalf("held text not sent while the upstream is idle (%d bytes got)", len(body))
		}
		check(t, aid, spans)
	})
	t.Run("llm", func(t *testing.T) {
		aid := &obsCountingAID{}
		insp, spans := obsBothInspector(aid)
		c := obsStreamStart(t, obsIdleLLM(t, insp, deltas, gap), bound)
		tail := strings.Join(deltas[len(deltas)-3:], "")
		if body, ok := c.waitFor(bound, func(body string, _ bool) bool {
			return strings.Count(body, `"content":`) >= len(deltas) && strings.Contains(streamTailLLMText(body), tail)
		}); !ok {
			t.Fatalf("held chunks not sent while the provider is idle (%d bytes got)", len(body))
		}
		check(t, aid, spans)
	})
	// The finding is followed by more than 500 bytes of text, so a full
	// check reads it before the upstream goes idle.
	marked := append(append(append(append([]string(nil), deltas[:100]...), " zq-aid-marker-0625 "), streamTailDeltas(800, size)...), "closing zq-0625-aid-end")
	t.Run("passthrough/aid-finding", func(t *testing.T) {
		aid := &obsCountingAID{marker: "zq-aid-marker-0625"}
		insp, _ := obsBothInspector(aid)
		c := obsStreamStart(t, obsIdleUpstream(t, f, insp, marked, gap), bound)
		body, ok := c.waitFor(bound, func(_ string, ended bool) bool { return ended })
		if !ok || streamTailSentTerminal(f, body) || strings.Contains(body, "zq-0625-aid-end") {
			t.Fatalf("an AI Defense finding did not end the stream: ended=%v terminal=%v", ok, streamTailSentTerminal(f, body))
		}
	})
	t.Run("llm/aid-finding", func(t *testing.T) {
		aid := &obsCountingAID{marker: "zq-aid-marker-0625"}
		insp, _ := obsBothInspector(aid)
		c := obsStreamStart(t, obsIdleLLM(t, insp, marked, gap), bound)
		body, ok := c.waitFor(bound, func(_ string, ended bool) bool { return ended })
		if !ok || !strings.Contains(body, "content blocked mid-stream by guardrail") || strings.Contains(body, "zq-0625-aid-end") {
			t.Fatalf("an AI Defense finding did not end the stream: ended=%v", ok)
		}
	})
}

// streamTailLLMText is the delta text of an /llm SSE body.
func streamTailLLMText(body string) string {
	var sb strings.Builder
	for _, line := range strings.Split(body, "\n") {
		data, ok := strings.CutPrefix(strings.TrimSpace(line), "data: ")
		if !ok || data == "[DONE]" {
			continue
		}
		var ch StreamChunk
		if err := json.Unmarshal([]byte(data), &ch); err != nil {
			continue
		}
		for _, c := range ch.Choices {
			if c.Delta != nil {
				sb.WriteString(c.Delta.Content)
			}
		}
	}
	return sb.String()
}

// obsRecordingInspector records the completion text every check reads and
// flags the marker in it.
type obsRecordingInspector struct {
	*mockInspector
	mu   sync.Mutex
	seen []string
}

func (i *obsRecordingInspector) read(direction, content string) *ScanVerdict {
	if direction != "completion" {
		return &ScanVerdict{Action: "allow", Severity: "NONE"}
	}
	i.mu.Lock()
	i.seen = append(i.seen, content)
	i.mu.Unlock()
	if strings.Contains(content, streamTailMarker) {
		return &ScanVerdict{Action: "block", Severity: "HIGH", Reason: "stream tail marker", Findings: []string{"test:stream-tail"}}
	}
	return &ScanVerdict{Action: "allow", Severity: "NONE"}
}

func (i *obsRecordingInspector) Inspect(_ context.Context, direction, content string, _ []ChatMessage, _, _ string) *ScanVerdict {
	return i.read(direction, content)
}

func (i *obsRecordingInspector) InspectMidStream(_ context.Context, direction, content string, _ []ChatMessage, _, _ string) *ScanVerdict {
	return i.read(direction, content)
}

func (i *obsRecordingInspector) sawMarker() bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	for _, s := range i.seen {
		if strings.Contains(s, streamTailMarker) {
			return true
		}
	}
	return false
}

// The reply extractor reads every model text the client renders
// (rel-1-0-10:GAP-0687, the GAP-0370 family): Gemini inlineData of a text
// media type (base64-decoded), streamed and buffered, and the revised_prompt
// of a Responses image_generation_call (already read on da4177e225, pinned
// here). The image bytes beside them stay unread, and a benign one passes.
func TestGAP0687ReplyExtractorReadsImagePromptAndTextInlineData(t *testing.T) {
	img := strings.Repeat("iVBORw0KGgoAAAANSUhEUgAA", 8)
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	resp := streamTailFormatNamed(t, "openai-responses")
	gem := streamTailFormatNamed(t, "gemini")
	imageItem := func(prompt string) map[string]any {
		return map[string]any{"type": "image_generation_call", "id": "ig_1", "status": "completed", "revised_prompt": prompt, "result": img}
	}
	textPart := func(mime, text string) map[string]any {
		return map[string]any{"inlineData": map[string]any{"mimeType": mime, "data": b64(text)}}
	}
	streamed := []struct {
		name string
		f    streamTailFormat
		line func(text string) string
	}{
		{"responses/output_item.done", resp, func(text string) string {
			return "event: response.output_item.done\ndata: " + streamTailJSON(map[string]any{"type": "response.output_item.done", "output_index": 1, "item": imageItem(text)}) + "\n\n"
		}},
		{"responses/completed", resp, func(text string) string {
			return "event: response.completed\ndata: " + streamTailJSON(map[string]any{"type": "response.completed", "response": map[string]any{"id": "resp_1", "status": "completed", "output": []any{imageItem(text)}}}) + "\n\n"
		}},
		{"gemini/inlineData-text-plain", gem, func(text string) string {
			return streamTailGeminiEvent(0, []any{textPart("text/plain", text)}, nil)
		}},
		{"gemini/inline_data-text-markdown", gem, func(text string) string {
			return streamTailGeminiEvent(0, []any{map[string]any{"inline_data": map[string]any{"mime_type": "text/markdown", "data": b64(text)}}}, nil)
		}},
	}
	for _, c := range streamed {
		for _, finding := range []bool{true, false} {
			t.Run(fmt.Sprintf("stream/%s/finding=%v", c.name, finding), func(t *testing.T) {
				text := "a picture of a lighthouse at dusk"
				if finding {
					text += " " + streamTailMarker
				}
				body := c.f.head + c.f.delta(streamTailProse(200)) + c.line(text) + c.f.delta(streamTailProse(100)) + c.f.tail + c.f.terminal
				up := streamTailRawUpstream(t, c.f, body, 4<<10)
				insp := &obsRecordingInspector{mockInspector: newMockInspector()}
				proxy := streamTailProxy(t, c.f.provider, insp, "action")
				out, _ := streamTailServe(t, proxy, c.f, up.URL)
				if finding != insp.sawMarker() {
					t.Fatalf("the checks read the marker: %v, want %v", insp.sawMarker(), finding)
				}
				if finding == streamTailSentTerminal(c.f, out) {
					t.Fatalf("finding=%v but the stream ended as a finished reply=%v", finding, streamTailSentTerminal(c.f, out))
				}
			})
		}
	}
	buffered := []struct {
		name, provider, path string
		reply                func(text string) map[string]any
	}{
		{"responses", "openai", "/v1/responses", func(text string) map[string]any {
			return map[string]any{"id": "resp_1", "object": "response", "status": "completed", "output": []any{imageItem(text)}}
		}},
		{"gemini", "gemini", "/v1beta/models/gemini-test:generateContent", func(text string) map[string]any {
			return map[string]any{"candidates": []any{map[string]any{"content": map[string]any{"role": "model", "parts": []any{textPart("text/plain", text)}}, "finishReason": "STOP", "index": 0}}}
		}},
	}
	textBytes := func(mime string, raw []byte) map[string]any {
		return map[string]any{"inlineData": map[string]any{"mimeType": mime, "data": base64.StdEncoding.EncodeToString(raw)}}
	}
	utf16le := func(s string) []byte {
		out := []byte{0xFF, 0xFE}
		for _, r := range s {
			out = append(out, byte(r), byte(r>>8))
		}
		return out
	}
	gemReply := func(part map[string]any) map[string]any {
		return map[string]any{"candidates": []any{map[string]any{"content": map[string]any{"role": "model", "parts": []any{part}}, "finishReason": "STOP", "index": 0}}}
	}
	buffered = append(buffered,
		struct {
			name, provider, path string
			reply                func(text string) map[string]any
		}{"gemini/utf-16", "gemini", "/v1beta/models/gemini-test:generateContent", func(text string) map[string]any {
			return gemReply(textBytes("text/plain; charset=utf-16", utf16le(text)))
		}},
		struct {
			name, provider, path string
			reply                func(text string) map[string]any
		}{"gemini/latin-1", "gemini", "/v1beta/models/gemini-test:generateContent", func(text string) map[string]any {
			return gemReply(textBytes("text/plain; charset=iso-8859-1", append([]byte{'c', 'a', 'f', 0xE9, ' '}, text...)))
		}},
	)
	for _, c := range buffered {
		for _, finding := range []bool{true, false} {
			t.Run(fmt.Sprintf("buffered/%s/finding=%v", c.name, finding), func(t *testing.T) {
				text := "a picture of a lighthouse at dusk"
				if finding {
					text += " " + streamTailMarker
				}
				raw := mustJSON(t, c.reply(text))
				up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write(raw)
				}))
				t.Cleanup(up.Close)
				insp := &obsRecordingInspector{mockInspector: newMockInspector()}
				proxy := streamTailProxy(t, c.provider, insp, "action")
				f := streamTailFormat{path: c.path}
				out, _ := streamTailServe(t, proxy, f, up.URL)
				if finding != insp.sawMarker() {
					t.Fatalf("the checks read the marker: %v, want %v", insp.sawMarker(), finding)
				}
				if !finding && out != string(raw) {
					t.Fatalf("a benign reply changed: %s", out)
				}
				if finding && strings.Contains(out, img) {
					t.Fatalf("a refused reply reached the client: %s", out)
				}
			})
		}
	}
}
