package gateway

// Scratch latency probe for s7/response-fields (never committed). Runs only
// with RF_LATENCY=1. Passthrough streams through the real local inspector:
// prose (Anthropic text_delta, OpenAI chat-shape deltas) and a tool-call
// stream (Anthropic input_json_delta), 16-byte deltas, one flush per event.

import (
	"bufio"
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

func rfProse(n int) string {
	words := []string{"the", "gateway", "reads", "every", "field", "of", "a", "model", "answer", "before", "release,", "and", "checks", "it", "against", "the", "pack."}
	var sb strings.Builder
	for i := 0; sb.Len() < n; i++ {
		sb.WriteString(words[i%len(words)])
		if i%23 == 22 {
			sb.WriteString("\n")
		} else {
			sb.WriteString(" ")
		}
	}
	return sb.String()[:n]
}

func rfEvents(kind string, text string) []string {
	var out []string
	for i := 0; i < len(text); i += 16 {
		j := min(i+16, len(text))
		b, _ := json.Marshal(text[i:j])
		switch kind {
		case "anthropic-text":
			out = append(out, `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":`+string(b)+`}}`)
		case "anthropic-tool":
			out = append(out, `{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":`+string(b)+`}}`)
		case "responses-text":
			out = append(out, `{"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":`+string(b)+`}`)
		case "responses-tool":
			out = append(out, `{"type":"response.function_call_arguments.delta","output_index":1,"delta":`+string(b)+`}`)
		case "chat-text":
			out = append(out, `{"choices":[{"index":0,"delta":{"content":`+string(b)+`}}]}`)
		}
	}
	return out
}

func rfOnce(t *testing.T, provider, path string, events []string) (ttfb, total time.Duration, n int) {
	pace := time.Duration(0)
	if os.Getenv("RF_PACE_US") != "" {
		var us int
		fmt.Sscanf(os.Getenv("RF_PACE_US"), "%d", &us)
		pace = time.Duration(us) * time.Microsecond
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fl := w.(http.Flusher)
		next := time.Now()
		for _, e := range events {
			if pace > 0 {
				next = next.Add(pace)
				time.Sleep(time.Until(next))
			}
			_, _ = io.WriteString(w, "data: "+e+"\n\n")
			fl.Flush()
		}
	}))
	defer upstream.Close()
	registerRawForwardProviderDomain(t, upstream.URL, provider)
	allowRawForwardPrivateTargets(t)
	proxy := newTestProxy(t, &mockProvider{}, NewGuardrailInspector("local", nil, nil), "action")
	srv := httptest.NewServer(http.HandlerFunc(proxy.handlePassthrough))
	defer srv.Close()
	body := `{"model":"claude-x","max_tokens":16,"messages":[{"role":"user","content":"hi"}],"stream":true}`
	if provider == "openai" {
		body = `{"model":"gpt-x","input":"hi","stream":true}`
	}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DC-Target-URL", upstream.URL)
	req.Header.Set("X-AI-Auth", "Bearer test-key")
	start := time.Now()
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	r := bufio.NewReader(resp.Body)
	if _, err := r.ReadByte(); err != nil {
		t.Fatalf("no first byte: %v", err)
	}
	ttfb = time.Since(start)
	rest, _ := io.ReadAll(r)
	total = time.Since(start)
	return ttfb, total, len(rest) + 1
}

func median(d []time.Duration) time.Duration {
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	return d[len(d)/2]
}

func TestRFLatency(t *testing.T) {
	if os.Getenv("RF_LATENCY") != "1" {
		t.Skip("RF_LATENCY=1")
	}
	runs := 7
	if os.Getenv("RF_RUNS") != "" {
		fmt.Sscanf(os.Getenv("RF_RUNS"), "%d", &runs)
	}
	type c struct {
		name, provider, path, kind string
		size                       int
	}
	only := os.Getenv("RF_ONLY")
	for _, cs := range []c{
		{"prose-20KiB-responses", "openai", "/v1/responses", "responses-text", 20 << 10},
		{"prose-200KiB-responses", "openai", "/v1/responses", "responses-text", 200 << 10},
		{"toolcall-20KiB-responses", "openai", "/v1/responses", "responses-tool", 20 << 10},
		{"prose-20KiB-anthropic", "anthropic", "/v1/messages", "anthropic-text", 20 << 10},
		{"prose-200KiB-anthropic", "anthropic", "/v1/messages", "anthropic-text", 200 << 10},
		{"prose-20KiB-chatshape", "openai", "/v1/completions", "chat-text", 20 << 10},
		{"prose-200KiB-chatshape", "openai", "/v1/completions", "chat-text", 200 << 10},
		{"toolcall-4KiB-anthropic", "anthropic", "/v1/messages", "anthropic-tool", 4 << 10},
		{"toolcall-20KiB-anthropic", "anthropic", "/v1/messages", "anthropic-tool", 20 << 10},
		{"toolcall-200KiB-anthropic", "anthropic", "/v1/messages", "anthropic-tool", 200 << 10},
	} {
		if only != "" && !strings.Contains(cs.name, only) {
			continue
		}
		events := rfEvents(cs.kind, rfProse(cs.size))
		var tt, tot []time.Duration
		bytes := 0
		for i := 0; i < runs; i++ {
			a, b, n := rfOnce(t, cs.provider, cs.path, events)
			tt, tot, bytes = append(tt, a), append(tot, b), n
		}
		fmt.Printf("RFLAT %s ttfb_ms=%.2f total_ms=%.1f bytes=%d events=%d\n", cs.name,
			float64(median(tt).Microseconds())/1000, float64(median(tot).Microseconds())/1000, bytes, len(events))
	}
}
