// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// covSyncRecorder is the client side of a proxy call, in memory: what the
// proxy has written is in it the moment Write returns, so a test that has
// waited for the proxy (streamReadForTest) reads exactly what the agent has.
type covSyncRecorder struct {
	mu   sync.Mutex
	hdr  http.Header
	code int
	body bytes.Buffer
}

func (r *covSyncRecorder) Header() http.Header {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.hdr == nil {
		r.hdr = http.Header{}
	}
	return r.hdr
}
func (r *covSyncRecorder) WriteHeader(c int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.code == 0 {
		r.code = c
	}
}
func (r *covSyncRecorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.body.Write(p)
}
func (r *covSyncRecorder) Flush() {}
func (r *covSyncRecorder) bytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]byte(nil), r.body.Bytes()...)
}

// covHeldProxy is a proxy in action mode with the test-only tool-call seam.
func covHeldProxy(t *testing.T) *GuardrailProxy {
	t.Helper()
	proxy := newTestProxy(t, &mockProvider{}, &covInspector{}, "action")
	proxy.toolCallVerdictForTest = covToolVerdict
	return proxy
}

// covHeldRun runs one proxy call against an upstream that stops inside a
// call: send writes what comes before the stop and returns the number of
// bytes it wrote; the upstream then waits for the test. The returned early
// is what the agent has once the proxy has read everything sent so far, with
// no sleep: the proxy reports each read it has fully handled
// (streamReadForTest), and the test waits for the count of bytes sent. final
// is what the agent has when the reply ends.
func covHeldRun(t *testing.T, proxy *GuardrailProxy, path, reqProvider, ctype string, req []byte,
	send func(w io.Writer, flush func()) int, rest func(w io.Writer, flush func())) (early, final []byte) {
	t.Helper()
	gate := make(chan struct{})
	sentCh := make(chan int, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", ctype)
		fl, _ := w.(http.Flusher)
		flush := func() {
			if fl != nil {
				fl.Flush()
			}
		}
		sentCh <- send(w, flush)
		select {
		case <-gate:
		case <-time.After(30 * time.Second):
		}
		rest(w, flush)
	}))
	t.Cleanup(srv.Close)
	host := strings.TrimPrefix(srv.URL, "http://")
	if i := strings.Index(host, ":"); i > 0 {
		host = host[:i]
	}
	orig := providerDomains
	providerDomains = append(providerDomains, struct {
		domain string
		name   string
	}{host, reqProvider})
	t.Cleanup(func() { providerDomains = orig })

	var read atomic.Int64
	notify := make(chan struct{}, 1)
	proxy.streamReadForTest = func(total int) {
		read.Store(int64(total))
		select {
		case notify <- struct{}{}:
		default:
		}
	}
	rec := &covSyncRecorder{}
	hreq := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(req))
	hreq.Header.Set("Content-Type", "application/json")
	hreq.Header.Set("X-DC-Target-URL", srv.URL)
	hreq.Header.Set("X-AI-Auth", "Bearer test-key")
	hreq.RemoteAddr = "127.0.0.1:12345"
	done := make(chan struct{})
	go func() {
		defer close(done)
		proxy.handlePassthrough(rec, hreq)
	}()

	timeout := time.After(60 * time.Second)
	select {
	case sent := <-sentCh:
		// Wait until the proxy has handled every byte sent, or ended.
	wait:
		for read.Load() < int64(sent) {
			select {
			case <-notify:
			case <-done:
				break wait
			case <-timeout:
				close(gate)
				t.Fatalf("the proxy did not read the %d bytes sent (read %d)", sent, read.Load())
			}
		}
	case <-done:
	case <-timeout:
		close(gate)
		t.Fatal("the upstream never sent")
	}
	early = rec.bytes()
	close(gate)
	select {
	case <-done:
	case <-timeout:
		t.Fatal("the reply did not end")
	}
	return early, rec.bytes()
}

// P4: a streamed call is held until its verdict. The upstream stops inside
// the call; once the proxy has handled every byte sent, the agent has
// received no byte of the call, and when the call ends blocked it never
// does, also when the text before the call already crossed the initial
// buffer and when the open call is larger than the initial buffer cap. All
// eight SSE framings, Responses, Chat Completions, Anthropic and Gemini.
func TestPassthroughCoverageHeldCallProperty(t *testing.T) {
	covAllowPrivate(t)
	type held struct {
		name   string
		path   string
		wire   string
		before func(n int) []string // events before the call: text of about n bytes
		pad    func(s string) string
		open   []string // events from the start of the call to just before its end
		close  []string // the rest
		marks  []string // strings that must not arrive
	}
	enc := func(v any) string { b, _ := json.Marshal(v); return string(b) }
	cases := []held{
		{name: "responses", path: "/v1/responses", wire: "openai",
			before: func(n int) []string {
				return []string{enc(map[string]any{"type": "response.output_text.delta", "item_id": "msg_1", "delta": strings.Repeat("working on it. ", n/15+1)})}
			},
			pad: func(s string) string {
				return enc(map[string]any{"type": "response.output_text.delta", "item_id": "msg_1", "delta": s})
			},
			open: []string{`{"type":"response.output_item.added","output_index":1,"item":{"id":"fc_1","type":"function_call","call_id":"call_1","name":"` + covBlockedTool + `","arguments":""}}`,
				`{"type":"response.function_call_arguments.delta","output_index":1,"item_id":"fc_1","delta":"{\"note\":"}`},
			close: []string{`{"type":"response.function_call_arguments.delta","output_index":1,"item_id":"fc_1","delta":"\"x\"}"}`,
				`{"type":"response.output_item.done","output_index":1,"item":{"id":"fc_1","type":"function_call","call_id":"call_1","name":"` + covBlockedTool + `","arguments":"{\"note\":\"x\"}"}}`,
				`{"type":"response.completed","response":{"id":"resp_1","status":"completed"}}`},
			marks: []string{covBlockedTool, "call_1", "function_call"}},
		{name: "chat", path: "/v1/completions", wire: "openai",
			before: func(n int) []string {
				return []string{enc(map[string]any{"choices": []any{map[string]any{"index": 0, "delta": map[string]any{"content": strings.Repeat("working on it. ", n/15+1)}}}})}
			},
			pad: func(s string) string {
				return enc(map[string]any{"choices": []any{map[string]any{"index": 0, "delta": map[string]any{"content": s}}}})
			},
			open: []string{`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"` + covBlockedTool + `","arguments":"{\"note\":"}}]}}]}`},
			close: []string{`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"x\"}"}}]}}]}`,
				`{"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`, `[DONE]`},
			marks: []string{covBlockedTool, "call_1", "tool_calls"}},
		{name: "anthropic", path: "/v1/messages", wire: "anthropic",
			before: func(n int) []string {
				return []string{`{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
					enc(map[string]any{"type": "content_block_delta", "index": 0, "delta": map[string]any{"type": "text_delta", "text": strings.Repeat("working on it. ", n/15+1)}}),
					`{"type":"content_block_stop","index":0}`}
			},
			pad: func(s string) string {
				return enc(map[string]any{"type": "ping", "pad": s})
			},
			open: []string{`{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"tu_1","name":"` + covBlockedTool + `","input":{}}}`,
				`{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"note\":"}}`},
			close: []string{`{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"\"x\"}"}}`, `{"type":"content_block_stop","index":1}`,
				`{"type":"message_delta","delta":{"stop_reason":"tool_use"}}`, `{"type":"message_stop"}`},
			marks: []string{covBlockedTool, "tu_1", "tool_use"}},
		// Gemini sends a call whole, in one event: the event is held until its
		// verdict and never reaches the agent.
		{name: "gemini", path: "/v1beta/models/dc-test:streamGenerateContent", wire: "gemini",
			before: func(n int) []string {
				return []string{enc(map[string]any{"candidates": []any{map[string]any{"content": map[string]any{"role": "model", "parts": []any{map[string]any{"text": strings.Repeat("working on it. ", n/15+1)}}}}}})}
			},
			pad: func(s string) string {
				return enc(map[string]any{"candidates": []any{map[string]any{"content": map[string]any{"role": "model", "parts": []any{map[string]any{"text": s}}}}}})
			},
			open:  []string{`{"candidates":[{"content":{"role":"model","parts":[{"functionCall":{"name":"` + covBlockedTool + `","args":{"note":"x"}}}]}}]}`},
			close: []string{`{"candidates":[{"content":{"role":"model","parts":[{"text":"done"}]},"finishReason":"STOP"}]}`},
			marks: []string{covBlockedTool, "functionCall"}},
	}
	req := covJSON(t, map[string]any{"model": "dc-test-model", "input": "hello there", "messages": []any{map[string]any{"role": "user", "content": "hello there"}},
		"contents": []any{map[string]any{"role": "user", "parts": []any{map[string]any{"text": "hello there"}}}}})
	leads, sizes := []int{10, 2000}, []int{0, 1300 << 10} // text before the call: inside, and past, the initial buffer; text inside the open call: none, and past the 1 MiB cap
	pick := covPick(covSample(t, "TestPassthroughCoverageHeldCallProperty",
		[]string{"wire", "lead", "size", "framing", "mode"}, []int{len(cases), len(leads), len(sizes), len(covFramings), 2},
		func(c []int) bool { return !(c[2] == 1 && c[4] == 0) }, // past the cap an OSS install may release the call with an alert
		nil))
	for ci, c := range cases {
		for li, lead := range leads {
			for zi, size := range sizes {
				for fi, fr := range covFramings {
					for mi, managed := range []bool{false, true} {
						if !pick(ci, li, zi, fi, mi) {
							continue
						}
						c, lead, size, fr, managed := c, lead, size, fr, managed
						t.Run(fmt.Sprintf("%s/lead=%d/size=%d/%s/managed=%v", c.name, lead, size, fr, managed), func(t *testing.T) {
							covSetManaged(t, managed)
							proxy := covHeldProxy(t)
							pad := strings.Repeat("padding text. ", 40)
							early, final := covHeldRun(t, proxy, c.path, c.wire, "text/event-stream", req,
								func(w io.Writer, flush func()) int {
									total := 0
									sendEvents := func(events []string) {
										b := covFrame(events, fr)
										if total > 0 {
											b = bytes.TrimPrefix(b, []byte("\xEF\xBB\xBF")) // the byte-order mark starts the stream only
										}
										_, _ = w.Write(b)
										flush()
										total += len(b)
									}
									sendEvents(c.before(lead))
									sendEvents(c.open)
									for n := 0; n < size; n += len(pad) {
										sendEvents([]string{c.pad(pad)})
									}
									return total
								},
								func(w io.Writer, flush func()) {
									_, _ = w.Write(bytes.TrimPrefix(covFrame(c.close, fr), []byte("\xEF\xBB\xBF")))
									flush()
								})
							for _, m := range c.marks {
								if bytes.Contains(early, []byte(m)) {
									t.Errorf("part of a held call reached the agent before its verdict (%q):\n%.300s", m, early)
								}
								if bytes.Contains(final, []byte(m)) {
									t.Errorf("a blocked call reached the agent (%q):\n%.300s", m, final)
								}
							}
						})
					}
				}
			}
		}
	}
}

// The same for a Bedrock stream (InvokeModelWithResponseStream and
// ConverseStream): the agent has no frame of the call before the verdict,
// whether the text before it crossed the initial buffer or not and at any
// split of the reads.
func TestPassthroughBedrockToolCallHeldUntilVerdict(t *testing.T) {
	covAllowPrivate(t)
	for _, st := range covBedrockStreams(t, covBlockedTool) {
		for _, buf := range []int{1, 0} {
			for _, split := range []int{0, 7, 100} { // 0: one write per frame
				st, buf, split := st, buf, split
				t.Run(fmt.Sprintf("%s/buffer=%d/split=%d", st.name, buf, split), func(t *testing.T) {
					wire := st.wire()
					// The upstream stops inside the call: after its first input part.
					stop := 0
					for i := 0; i <= st.toolFrom+1; i++ {
						stop += len(st.frames[i])
					}
					proxy := covHeldProxy(t)
					if proxy.cfg != nil && buf > 0 {
						proxy.cfg.StreamBufferBytes = buf
					}
					writeSplit := func(w io.Writer, flush func(), b []byte) {
						if split <= 0 {
							_, _ = w.Write(b)
							flush()
							return
						}
						for len(b) > 0 {
							n := min(split, len(b))
							_, _ = w.Write(b[:n])
							flush()
							b = b[n:]
						}
					}
					early, final := covHeldRun(t, proxy, st.path, "bedrock", "application/vnd.amazon.eventstream", []byte(`{"messages":[{"role":"user","content":[{"text":"hi"}]}]}`),
						func(w io.Writer, flush func()) int { writeSplit(w, flush, wire[:stop]); return stop },
						func(w io.Writer, flush func()) { writeSplit(w, flush, wire[stop:]) })
					for i := st.toolFrom; i <= st.toolTo; i++ {
						if bytes.Contains(early, st.frames[i]) {
							t.Errorf("frame %d of a held call reached the agent before its verdict", i)
						}
					}
					covBedrockCheckRefused(t, st, final, "after the verdict")
				})
			}
		}
	}
}
