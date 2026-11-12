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
