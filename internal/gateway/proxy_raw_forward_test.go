package gateway

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

func TestExtractRawForwardCompletionNonStreaming(t *testing.T) {
	body := []byte(`{
		"id": "chatcmpl-test",
		"object": "chat.completion",
		"choices": [
			{
				"index": 0,
				"message": {
					"role": "assistant",
					"content": "OK"
				},
				"finish_reason": "stop"
			}
		],
		"usage": {
			"prompt_tokens": 10,
			"completion_tokens": 2,
			"total_tokens": 12
		}
	}`)

	got, usage := extractRawForwardCompletion(body, false)
	if got != "OK" {
		t.Fatalf("completion = %q, want %q", got, "OK")
	}
	if usage == nil {
		t.Fatalf("usage = nil, want non-nil")
	}
	if usage.PromptTokens != 10 || usage.CompletionTokens != 2 {
		t.Fatalf("usage = %+v, want prompt=10 completion=2", usage)
	}
}

func TestExtractRawForwardCompletionStreaming(t *testing.T) {
	body := []byte(strings.Join([]string{
		`data: {"choices":[{"delta":{"content":"O"}}]}`,
		`data: {"choices":[{"delta":{"content":"K"}}]}`,
		`data: [DONE]`,
		``,
	}, "\n"))

	got, usage := extractRawForwardCompletion(body, true)
	if got != "OK" {
		t.Fatalf("completion = %q, want %q", got, "OK")
	}
	if usage != nil {
		t.Fatalf("usage = %+v, want nil for streaming chunks", usage)
	}
}

func TestExtractRawForwardCompletionIgnoresRawRequestText(t *testing.T) {
	body := []byte(`{
		"choices": [
			{
				"message": {
					"role": "assistant",
					"content": "OK"
				}
			}
		],
		"messages": [
			{
				"role": "system",
				"content": "SOUL.md AGENTS.md MEMORY.md"
			}
		]
	}`)

	got, _ := extractRawForwardCompletion(body, false)
	if got != "OK" {
		t.Fatalf("completion = %q, want assistant output only", got)
	}
}

func TestRawForwardUpstreamURLAvoidsDuplicatedVersionPrefix(t *testing.T) {
	got := rawForwardUpstreamURL("https://openrouter.ai/api/v1", "/v1/chat/completions?x=1")
	want := "https://openrouter.ai/api/v1/chat/completions?x=1"
	if got != want {
		t.Fatalf("rawForwardUpstreamURL = %q, want %q", got, want)
	}
}

func TestRawForwardNonStreamingInspectsToolCalls(t *testing.T) {
	var upstreamHits int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&upstreamHits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id":"chatcmpl-tool",
			"object":"chat.completion",
			"model":"gpt-4",
			"choices":[{
				"index":0,
				"message":{
					"role":"assistant",
					"tool_calls":[{
						"id":"call_1",
						"type":"function",
						"function":{"name":"bash","arguments":"{\"command\":\"rm -rf /\"}"}
					}]
				},
				"finish_reason":"tool_calls"
			}]
		}`))
	}))
	defer upstream.Close()

	registerRawForwardProviderDomain(t, upstream.URL, "openai")
	allowRawForwardPrivateTargets(t)

	proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
	body := mustJSON(t, map[string]interface{}{
		"model":    "gpt-4",
		"messages": []map[string]interface{}{{"role": "user", "content": "call a tool"}},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DC-Target-URL", upstream.URL)
	req.Header.Set("X-AI-Auth", "Bearer sk-test")
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()

	proxy.handleChatCompletion(rec, req)

	if atomic.LoadInt32(&upstreamHits) != 1 {
		t.Fatalf("expected one upstream hit, got %d", upstreamHits)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected blocked OpenAI-compatible 200 response, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "DefenseClaw") {
		t.Fatalf("expected DefenseClaw block response, got %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "rm -rf") {
		t.Fatalf("blocked raw tool call leaked to client: %s", rec.Body.String())
	}
}

func TestRawForwardStreamingFlushesChunksIncrementally(t *testing.T) {
	releaseSecond := make(chan struct{})
	defer func() {
		select {
		case <-releaseSecond:
		default:
			close(releaseSecond)
		}
	}()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("upstream ResponseWriter missing flusher")
		}
		_, _ = w.Write([]byte(`data: {"id":"s1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"A"}}]}` + "\n\n"))
		flusher.Flush()
		<-releaseSecond
		_, _ = w.Write([]byte(`data: {"id":"s1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"B"}}]}` + "\n\n"))
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
		flusher.Flush()
	}))
	defer upstream.Close()

	registerRawForwardProviderDomain(t, upstream.URL, "openai")
	allowRawForwardPrivateTargets(t)

	proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "observe")
	proxyServer := httptest.NewServer(http.HandlerFunc(proxy.handleChatCompletion))
	defer proxyServer.Close()

	body := mustJSON(t, map[string]interface{}{
		"model":    "gpt-4",
		"messages": []map[string]interface{}{{"role": "user", "content": "stream"}},
		"stream":   true,
	})
	req, err := http.NewRequest(http.MethodPost, proxyServer.URL+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DC-Target-URL", upstream.URL)
	req.Header.Set("X-AI-Auth", "Bearer sk-test")

	client := proxyServer.Client()
	client.Timeout = 5 * time.Second
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	defer resp.Body.Close()

	reader := bufio.NewReader(resp.Body)
	firstLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read first SSE line: %v", err)
	}
	if !strings.Contains(firstLine, `"content":"A"`) {
		t.Fatalf("first raw SSE chunk = %q", firstLine)
	}
	close(releaseSecond)
	rest, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read remaining stream: %v", err)
	}
	bodyText := firstLine + string(rest)
	if !strings.Contains(bodyText, `"content":"B"`) || !strings.Contains(bodyText, "data: [DONE]") {
		t.Fatalf("stream response missing final chunks: %q", bodyText)
	}
}

func TestRawForwardPreservesHeadersAndAzureAuth(t *testing.T) {
	var gotOrg, gotProject, gotAuth, gotAPIKey string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotOrg = r.Header.Get("Openai-Organization")
		gotProject = r.Header.Get("Openai-Project")
		gotAuth = r.Header.Get("Authorization")
		gotAPIKey = r.Header.Get("api-key")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-raw","object":"chat.completion","model":"gpt-4","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`))
	}))
	defer upstream.Close()

	registerRawForwardProviderDomain(t, upstream.URL, "azure")
	allowRawForwardPrivateTargets(t)

	proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "observe")
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	proxy.bindObservabilityV8Trace(runtime)
	body := mustJSON(t, map[string]interface{}{
		"model":    "gpt-4",
		"messages": []map[string]interface{}{{"role": "user", "content": "hello"}},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DC-Target-URL", upstream.URL)
	req.Header.Set("X-AI-Auth", "Bearer azure-key")
	req.Header.Set("OpenAI-Organization", "org_123")
	req.Header.Set("OpenAI-Project", "proj_456")
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()

	proxy.handleChatCompletion(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if gotOrg != "org_123" || gotProject != "proj_456" {
		t.Fatalf("forwarded headers = org %q project %q", gotOrg, gotProject)
	}
	if gotAuth != "" {
		t.Fatalf("Azure raw forward should not send Authorization, got %q", gotAuth)
	}
	if gotAPIKey != "azure-key" {
		t.Fatalf("Azure api-key = %q, want azure-key", gotAPIKey)
	}
	var forwarded int64
	for _, metric := range capture.metricSnapshot() {
		if metric.Descriptor().Name != observability.TelemetryInstrumentDefenseClawGatewayForwardedHeaders {
			continue
		}
		if attributes := metric.Attributes(); attributes["defenseclaw.metric.path"] != "chat-completions" ||
			attributes["defenseclaw.metric.result"] != "ok" {
			t.Fatalf("generated forwarded-header attributes=%v", attributes)
		}
		value, ok := metric.Value().Int64()
		if !ok {
			t.Fatalf("generated forwarded-header value=%v", metric.Value())
		}
		forwarded += value
	}
	// Content-Type plus the two allowed OpenAI metadata headers are forwarded.
	if forwarded != 3 {
		t.Fatalf("generated forwarded-header count=%d want=3", forwarded)
	}
}

func registerRawForwardProviderDomain(t *testing.T, rawURL, provider string) {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}
	registerForwardingProviderDomain(t, u.Hostname(), provider)
}

func allowRawForwardPrivateTargets(t *testing.T) {
	t.Helper()
	orig := passthroughAllowPrivateForTest
	passthroughAllowPrivateForTest = true
	t.Cleanup(func() { passthroughAllowPrivateForTest = orig })
}
