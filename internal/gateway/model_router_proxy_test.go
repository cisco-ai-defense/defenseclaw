// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

type staticModelRouter struct {
	decision *ModelRouterDecision
}

func (r staticModelRouter) Route(context.Context, *ModelRouterInput) *ModelRouterDecision {
	return r.decision
}

func TestSemanticRouterRawForwardRewritesModelAndClearsOriginalCredential(t *testing.T) {
	var forwardedBody []byte
	var forwardedAuthorization string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		forwardedBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read upstream body: %v", err)
		}
		forwardedAuthorization = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-routed","object":"chat.completion","model":"qwen2.5:0.5b","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`))
	}))
	defer upstream.Close()

	proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	proxy.SetDefaultAgentName("zeptoclaw")
	proxy.bindObservabilityV8Trace(runtime)
	proxy.SetModelRouter(staticModelRouter{decision: &ModelRouterDecision{
		Provider:          "ollama",
		TargetURL:         upstream.URL,
		TargetURLOverride: true,
		Model:             "qwen2.5:0.5b",
		APIKeyOverride:    true,
		Reason:            "decision=small-route model=small confidence=1.00",
	}})

	body := mustJSON(t, map[string]interface{}{
		"model": "openai/gpt-4o",
		"messages": []map[string]interface{}{
			{"role": "user", "content": "Say hello."},
		},
		"parallel_tool_calls": true,
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DC-Target-URL", "https://api.openai.com")
	req.Header.Set("X-AI-Auth", "Bearer original-provider-secret")
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()

	proxy.handleChatCompletion(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("proxy status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if forwardedAuthorization != "" {
		t.Fatalf("router-selected keyless backend received original Authorization header %q", forwardedAuthorization)
	}
	var forwarded map[string]interface{}
	if err := json.Unmarshal(forwardedBody, &forwarded); err != nil {
		t.Fatalf("decode forwarded body: %v", err)
	}
	if got := forwarded["model"]; got != "qwen2.5:0.5b" {
		t.Fatalf("forwarded model = %#v, want qwen2.5:0.5b; body=%s", got, forwardedBody)
	}
	if got := forwarded["parallel_tool_calls"]; got != true {
		t.Fatalf("provider extension was not preserved: %#v", got)
	}
	if got := rec.Header().Get("X-Semantic-Router"); got != "routed" {
		t.Fatalf("X-Semantic-Router = %q, want routed", got)
	}
	agent, model := assertProxyGeneratedAgentModel(
		t, capture.snapshot(), observability.OutcomeCompleted, "Ok",
	)
	if agent.TraceID() != model.TraceID() {
		t.Fatalf("routed agent/model traces are disconnected: %s != %s", agent.TraceID(), model.TraceID())
	}
	attributes := proxyCanonicalAttributes(t, model.Record())
	if got := attributes["gen_ai.request.model"]; got != "qwen2.5:0.5b" {
		t.Fatalf("routed model trace request model = %#v, want qwen2.5:0.5b", got)
	}
}

func TestSemanticRouterRawForwardDropsOriginalCustomCredentialsAndUsesSelectedKey(t *testing.T) {
	allowRawForwardPrivateTargets(t)
	var forwardedHeaders http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwardedHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-routed","object":"chat.completion","model":"qwen2.5:0.5b","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`))
	}))
	defer upstream.Close()

	proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	proxy.bindObservabilityV8Trace(runtime)
	proxy.SetModelRouter(staticModelRouter{decision: &ModelRouterDecision{
		Provider:          "azure",
		TargetURL:         upstream.URL,
		TargetURLOverride: true,
		Model:             "qwen2.5:0.5b",
		APIKey:            "selected-provider-secret",
		APIKeyOverride:    true,
		Reason:            "decision=small-route model=small confidence=1.00",
	}})

	body := mustJSON(t, map[string]interface{}{
		"model": "openai/gpt-4o",
		"messages": []map[string]interface{}{
			{"role": "user", "content": "Say hello."},
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DC-Target-URL", "https://api.openai.com")
	req.Header.Set("X-AI-Auth", "Bearer original-provider-secret")
	req.Header.Set("Cookie", "session=original-provider-cookie")
	req.Header.Set("Proxy-Authorization", "Basic original-proxy-secret")
	req.Header.Set("X-Goog-Api-Key", "original-google-secret")
	req.Header.Set("OpenAI-Organization", "original-openai-org")
	req.Header.Set("Accept", "application/original-provider+json")
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()

	proxy.handleChatCompletion(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("proxy status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if got := forwardedHeaders.Get("api-key"); got != "selected-provider-secret" {
		t.Fatalf("selected Azure backend api-key = %q, want selected provider key", got)
	}
	if got := forwardedHeaders.Get("Authorization"); got != "" {
		t.Fatalf("selected Azure backend received bearer Authorization %q", got)
	}
	for _, name := range []string{
		"Cookie", "Proxy-Authorization", "X-Goog-Api-Key", "OpenAI-Organization", "Accept",
	} {
		if got := forwardedHeaders.Get(name); got != "" {
			t.Fatalf("router-selected backend received original %s header %q", name, got)
		}
	}
	for _, metric := range capture.metricSnapshot() {
		if metric.Descriptor().Name == observability.TelemetryInstrumentDefenseClawGatewayForwardedHeaders {
			t.Fatalf("routed request reported dropped custom headers as forwarded: %v", metric)
		}
	}
}

func TestTrustedRoutedLoopbackTargetIsNarrow(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8787/v1/chat/completions", nil)
	tests := []struct {
		name     string
		target   string
		provider string
		want     bool
	}{
		{name: "ollama alternate port", target: "http://127.0.0.1:11435", provider: "ollama", want: true},
		{name: "vllm ipv6 loopback", target: "http://[::1]:8000", provider: "vllm", want: true},
		{name: "proxy recursion", target: "http://127.0.0.1:8787", provider: "ollama", want: false},
		{name: "unrelated local service", target: "http://127.0.0.1:5432", provider: "openai", want: false},
		{name: "private network", target: "http://10.0.0.8:8000", provider: "vllm", want: false},
		{name: "userinfo", target: "http://user:pass@127.0.0.1:11435", provider: "ollama", want: false},
		{name: "missing port", target: "http://localhost", provider: "ollama", want: false},
		{name: "non http", target: "file://127.0.0.1:11435/tmp/model", provider: "ollama", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isTrustedRoutedLoopbackTarget(request, tt.target, tt.provider); got != tt.want {
				t.Fatalf("isTrustedRoutedLoopbackTarget(%q, %q) = %t, want %t", tt.target, tt.provider, got, tt.want)
			}
		})
	}
}
