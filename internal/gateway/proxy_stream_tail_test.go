// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// The tail of a streamed completion (rel-1-0-10:GAP-0212): the bytes after
// the last mid-stream scan are held until a check covers them, the final
// post-stream check is enforced in action mode, observe mode changes
// nothing, and the hold is bounded in time and bytes. The finding is a
// benign marker that a stub inspector flags, so no detection text is needed.

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

// streamTailFormat is one SSE wire format of a provider-native stream.
type streamTailFormat struct {
	name, provider, path string
	head, tail           string // events before the first and after the last text delta
	terminal             string // the event that ends the stream
	delta                func(text string) string
}

func streamTailJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

var streamTailFormats = []streamTailFormat{
	{
		name: "anthropic", provider: "anthropic", path: "/v1/messages",
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
		name: "openai-responses", provider: "openai", path: "/v1/responses",
		head:     "event: response.created\ndata: " + streamTailJSON(map[string]any{"type": "response.created", "response": map[string]any{"id": "resp_1", "model": "gpt-test"}}) + "\n\n",
		tail:     "event: response.output_text.done\ndata: {\"type\":\"response.output_text.done\",\"item_id\":\"msg_1\"}\n\n",
		terminal: "event: response.completed\ndata: " + streamTailJSON(map[string]any{"type": "response.completed", "response": map[string]any{"id": "resp_1", "status": "completed"}}) + "\n\n",
		delta: func(text string) string {
			return "event: response.output_text.delta\ndata: " + streamTailJSON(map[string]any{"type": "response.output_text.delta", "item_id": "msg_1", "delta": text}) + "\n\n"
		},
	},
}

// streamTailText is benign prose of n bytes cut into deltas of size bytes,
// with extra appended as the last delta(s).
func streamTailDeltas(n, size int, extra ...string) []string {
	const prose = "the stream carries plain words about lists and maps and loops. "
	var sb strings.Builder
	for sb.Len() < n {
		sb.WriteString(prose)
	}
	text := sb.String()[:n]
	var out []string
	for len(text) > 0 {
		k := min(size, len(text))
		out = append(out, text[:k])
		text = text[k:]
	}
	return append(out, extra...)
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
		w.Header().Set("Content-Type", "text/event-stream")
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

func streamTailServe(t *testing.T, proxy *GuardrailProxy, f streamTailFormat, upstream string) (string, string) {
	t.Helper()
	req := streamTailRequest(t, f, "", upstream)
	rec := httptest.NewRecorder()
	log := captureStderr(t, func() { proxy.handlePassthrough(rec, req) })
	return rec.Body.String(), log
}

// The final check covers the tail and is enforced: the marker in the last
// delta (after the last 500-byte scan) is never sent and the stream ends
// without its terminal event, as a mid-stream block ends it.
func TestStreamTailFinalCheckWithholdsTail(t *testing.T) {
	for _, f := range streamTailFormats {
		for _, mid := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/mid=%v", f.name, mid), func(t *testing.T) {
				insp := &streamTailInspector{mockInspector: newMockInspector(), final: true, mid: mid}
				up, _ := streamTailUpstream(t, f, streamTailDeltas(2400, 24, "and then "+streamTailMarker+" ends"), 0, nil)
				proxy := streamTailProxy(t, f.provider, insp, "action")
				out, log := streamTailServe(t, proxy, f, up.URL)
				if strings.Contains(out, streamTailMarker) {
					t.Fatalf("the tail marker reached the client")
				}
				if strings.Contains(out, f.terminal) {
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
			if strings.Contains(out, f.delta(streamTailMarker[half:])) || strings.Contains(out, f.terminal) {
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

// An SSE line that has not ended is held up to streamHoldMaxPartial; past it
// the stream is TRUNCATED (bound rule): the default pack alerts and sends
// it, the strict pack blocks it.
func TestStreamTailPartialLineBound(t *testing.T) {
	f := streamTailFormats[0] // a passthrough format (chat paths take handleChatCompletion)
	// Twice the bound, so the cap is crossed long before the line ends
	// (whatever the reads coalesce).
	long := "data: " + strings.Repeat("x", 2*streamHoldMaxPartial)
	for _, strict := range []bool{false, true} {
		t.Run(fmt.Sprintf("strict=%v", strict), func(t *testing.T) {
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				fl := w.(http.Flusher)
				_, _ = io.WriteString(w, f.head+f.delta(strings.Repeat("plain words ", 120)))
				fl.Flush()
				for i := 0; i < len(long); i += 32 << 10 {
					_, _ = io.WriteString(w, long[i:min(i+32<<10, len(long))])
					fl.Flush()
				}
				_, _ = io.WriteString(w, "\n\n"+f.terminal)
			}))
			defer up.Close()
			insp := &streamTailInspector{mockInspector: newMockInspector(), final: true, mid: true}
			proxy := streamTailProxy(t, f.provider, insp, "action")
			req := streamTailRequest(t, f, "", up.URL)
			if strict {
				cfg := &config.Config{}
				cfg.Guardrail.RulePack = "strict"
				req = req.WithContext(withPinnedGeneration(req.Context(), &Generation{N: 1, Config: cfg}))
			}
			rec := httptest.NewRecorder()
			log := captureStderr(t, func() { proxy.handlePassthrough(rec, req) })
			out := rec.Body.String()
			if strict {
				if strings.Contains(out, long[:streamHoldMaxPartial]) || strings.Contains(out, f.terminal) {
					t.Fatalf("strict pack sent a truncated line: %d bytes", len(out))
				}
				if !strings.Contains(log, "PASSTHROUGH-STREAM-BLOCK") {
					t.Fatalf("no block line: %s", log)
				}
				return
			}
			if !strings.Contains(out, long) || !strings.HasSuffix(out, f.terminal) {
				t.Fatalf("default pack did not send the stream: %d bytes", len(out))
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

// An upstream that stops inside an SSE line and stays open: the unfinished
// line is held at most streamHoldMaxPartialAge, then the stream is TRUNCATED
// (bound rule, cap time): the default pack alerts and sends what it held,
// the strict pack ends the stream. Every passthrough format.
func TestStreamTailStalledPartialLine(t *testing.T) {
	for _, f := range streamTailFormats {
		for _, strict := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/strict=%v", f.name, strict), func(t *testing.T) {
				const partial = "event: x\ndata: {\"type\":\"unfinished"
				stall := make(chan struct{})
				defer close(stall)
				up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "text/event-stream")
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
						cfg := &config.Config{}
						cfg.Guardrail.RulePack = "strict"
						r = r.WithContext(withPinnedGeneration(r.Context(), &Generation{N: 1, Config: cfg}))
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
				select {
				case out := <-got:
					if strict && strings.Contains(out, partial) {
						t.Fatal("the strict pack sent an unfinished line past the bound")
					}
					if !strict && !strings.Contains(out, partial) {
						t.Fatal("the default pack ended the stream instead of alerting")
					}
				case <-time.After(streamHoldMaxPartialAge + 3*time.Second):
					t.Fatalf("the unfinished line was held past %v", streamHoldMaxPartialAge)
				}
			})
		}
	}
}
