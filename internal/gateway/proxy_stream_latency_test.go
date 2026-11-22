// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

// TestStreamLatencyReport measures a streamed completion through the proxy
// (rel-1-0-10:GAP-0212 latency bar): time to first byte and total stream
// time at the client, p50 and p95, for the Anthropic and OpenAI Responses
// passthrough and the OpenAI chat /llm route, on a clean stream and on one
// with a finding in its last delta. The upstream stub sends 160 deltas of
// 24 bytes, one every 5 ms. The inspector is the local guardrail inspector
// (its regex cost included), with a benign marker as the finding. It runs
// only with DC_STREAM_LATENCY_OUT=<file> (one JSON line per cell), so a rel
// worktree can run the same file for the before side.
func TestStreamLatencyReport(t *testing.T) {
	out := os.Getenv("DC_STREAM_LATENCY_OUT")
	if out == "" {
		t.Skip("set DC_STREAM_LATENCY_OUT to run the stream latency report")
	}
	const (
		marker = "zq-latency-marker-51c2"
		deltas = 160
		size   = 24
		gap    = 5 * time.Millisecond
		runs   = 21
	)
	text := func(finding bool) []string {
		const prose = "the stream carries plain words about lists and maps and loops. "
		var sb strings.Builder
		for sb.Len() < deltas*size {
			sb.WriteString(prose)
		}
		s := sb.String()[:deltas*size]
		var d []string
		for i := 0; i < len(s); i += size {
			d = append(d, s[i:i+size])
		}
		if finding {
			d[len(d)-1] = marker
		}
		return d
	}
	js := func(v any) string { b, _ := json.Marshal(v); return string(b) }
	sse := map[string]func(string) string{
		"anthropic": func(d string) string {
			return "event: content_block_delta\ndata: " + js(map[string]any{"type": "content_block_delta", "index": 0, "delta": map[string]any{"type": "text_delta", "text": d}}) + "\n\n"
		},
		"responses": func(d string) string {
			return "event: response.output_text.delta\ndata: " + js(map[string]any{"type": "response.output_text.delta", "delta": d}) + "\n\n"
		},
	}
	terminal := map[string]string{
		"anthropic": "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
		"responses": "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\"}}\n\n",
	}
	path := map[string]string{"anthropic": "/v1/messages", "responses": "/v1/responses", "chat": "/v1/chat/completions"}
	pct := func(xs []time.Duration, p float64) float64 {
		s := append([]time.Duration(nil), xs...)
		sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
		return float64(s[min(len(s)-1, int(p*float64(len(s)-1)+0.5))].Microseconds()) / 1000
	}
	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	orig := providerDomains
	t.Cleanup(func() { providerDomains = orig })
	for _, format := range []string{"anthropic", "responses", "chat"} {
		provider := "anthropic"
		if format != "anthropic" {
			provider = "openai"
		}
		providerDomains = append(append([]providerDomainEntry(nil), orig...), providerDomainEntry{domain: "127.0.0.1", name: provider})
		for _, finding := range []bool{false, true} {
			d := text(finding)
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				fl := w.(http.Flusher)
				for _, x := range d {
					time.Sleep(gap)
					_, _ = io.WriteString(w, sse[format](x))
					fl.Flush()
				}
				_, _ = io.WriteString(w, terminal[format])
			}))
			insp := &latencyMarkerInspector{inner: NewGuardrailInspector("local", nil, nil), marker: marker}
			prov := &latencyStreamProvider{deltas: d, gap: gap}
			proxy := newTestProxy(t, prov, insp, "action")
			var handler http.HandlerFunc = proxy.handlePassthrough
			if format == "chat" {
				handler = proxy.handleChatCompletion
			}
			front := httptest.NewServer(handler)
			var ttfb, total []time.Duration
			blocked := 0
			for i := 0; i < runs; i++ {
				body, _ := json.Marshal(map[string]any{"model": "m", "stream": true, "messages": []map[string]any{{"role": "user", "content": "hello"}}})
				req, _ := http.NewRequest(http.MethodPost, front.URL+path[format], bytes.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				if format != "chat" {
					req.Header.Set("X-DC-Target-URL", up.URL)
					req.Header.Set("X-AI-Auth", "Bearer sk-test-upstream")
				}
				t0 := time.Now()
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				one := make([]byte, 1)
				if _, err := io.ReadFull(resp.Body, one); err != nil {
					t.Fatalf("%s: no first byte: %v", format, err)
				}
				ttfb = append(ttfb, time.Since(t0))
				rest, _ := io.ReadAll(resp.Body)
				total = append(total, time.Since(t0))
				resp.Body.Close()
				if bytes.Contains(rest, []byte("blocked")) || (format != "chat" && !bytes.HasSuffix(rest, []byte(terminal[format]))) {
					blocked++
				}
			}
			front.Close()
			up.Close()
			row := map[string]any{"format": format, "finding": finding, "runs": runs, "deltas": deltas, "delta_bytes": size, "gap_ms": gap.Milliseconds(),
				"ttfb_p50_ms": pct(ttfb, 0.5), "ttfb_p95_ms": pct(ttfb, 0.95), "total_p50_ms": pct(total, 0.5), "total_p95_ms": pct(total, 0.95), "blocked": blocked}
			line, _ := json.Marshal(row)
			fmt.Fprintln(f, string(line))
			t.Log(string(line))
		}
	}
}

type latencyMarkerInspector struct {
	inner  ContentInspector
	marker string
}

func (l *latencyMarkerInspector) mark(direction, content string, v *ScanVerdict) *ScanVerdict {
	if direction == "completion" && strings.Contains(content, l.marker) {
		return &ScanVerdict{Action: "block", Severity: "HIGH", Reason: "latency marker", Findings: []string{"test:latency-marker"}}
	}
	return v
}

func (l *latencyMarkerInspector) Inspect(ctx context.Context, direction, content string, messages []ChatMessage, model, mode string) *ScanVerdict {
	return l.mark(direction, content, l.inner.Inspect(ctx, direction, content, messages, model, mode))
}

func (l *latencyMarkerInspector) InspectMidStream(ctx context.Context, direction, content string, messages []ChatMessage, model, mode string) *ScanVerdict {
	return l.mark(direction, content, l.inner.InspectMidStream(ctx, direction, content, messages, model, mode))
}

func (l *latencyMarkerInspector) SetScannerMode(string)      {}
func (l *latencyMarkerInspector) SetHILTConfig(bool, string) {}

type latencyStreamProvider struct {
	mockProvider
	deltas []string
	gap    time.Duration
}

func (l *latencyStreamProvider) ChatCompletionStream(ctx context.Context, _ *ChatRequest, cb func(StreamChunk)) (*ChatUsage, error) {
	for _, d := range l.deltas {
		select {
		case <-time.After(l.gap):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		cb(StreamChunk{ID: "c1", Object: "chat.completion.chunk", Model: "m", Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{Content: d}}}})
	}
	stop := "stop"
	cb(StreamChunk{ID: "c1", Object: "chat.completion.chunk", Model: "m", Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{}, FinishReason: &stop}}})
	return &ChatUsage{}, nil
}
