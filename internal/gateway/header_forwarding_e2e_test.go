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
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/maximhq/bifrost/core/schemas"
)

// ---------------------------------------------------------------------------
// Slice-2 test fixtures. Independent of the Responses-API hydration
// fallback (PR fix/passthrough-direct-provider-hydration) — every test
// here sets X-DC-Target-URL on the inbound request and uses an httptest
// upstream so the feature is exercised without depending on the
// hydration code path.
// ---------------------------------------------------------------------------

func boolPtr(b bool) *bool { return &b }

// newForwardingProxy constructs a GuardrailProxy used by the
// passthrough-path tests. The proxy is wired to an httptest upstream
// via providerDomains registration so the three-branch passthrough
// policy classifies the request as "known" and forwards it.
func newForwardingProxy(t *testing.T, upstreamURL string) *GuardrailProxy {
	t.Helper()
	cfg := &config.GuardrailConfig{
		Enabled:   true,
		Model:     "openai/gpt-4",
		ModelName: "gpt-4",
		Port:      0,
		Mode:      "observe",
		LLM:       config.LLMConfig{Model: "openai/gpt-4"},
	}
	store, logger := testStoreAndLogger(t)
	p := &GuardrailProxy{
		cfg:             cfg,
		logger:          logger,
		health:          NewSidecarHealth(),
		store:           store,
		dataDir:         t.TempDir(),
		inspector:       newMockInspector(),
		mode:            "observe",
		skipAuthForTest: true,
	}
	p.resolveProviderFn = func(_ *ChatRequest) LLMProvider { return &mockProvider{} }
	u, err := url.Parse(upstreamURL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}
	registerForwardingProviderDomain(t, u.Hostname(), "openai")
	return p
}

// registerForwardingProviderDomain appends a (domain, provider) entry
// to providerDomains for the duration of the test.
func registerForwardingProviderDomain(t *testing.T, domain, provider string) {
	t.Helper()
	orig := providerDomains
	providerDomains = append(append([]providerDomainEntry{}, orig...),
		providerDomainEntry{domain: domain, name: provider})
	t.Cleanup(func() { providerDomains = orig })
}

// postPassthrough fires an X-DC-Target-URL-attached passthrough
// request at the proxy.
func postPassthrough(t *testing.T, proxy *GuardrailProxy, targetURL, path string, headers map[string]string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DC-Target-URL", targetURL)
	req.Header.Set("X-AI-Auth", "Bearer sk-upstream")
	for k, v := range headers {
		req.Header[k] = []string{v}
	}
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	proxy.handlePassthrough(rec, req)
	return rec
}

// ---------------------------------------------------------------------------
// Passthrough tests
// ---------------------------------------------------------------------------

// TestPassthrough_ForwardsAllowedHeaders verifies that an inbound
// custom header (not on the blocklist) reaches the upstream provider
// and that the canonical Authorization is re-minted from X-AI-Auth.
func TestPassthrough_ForwardsAllowedHeaders(t *testing.T) {
	var (
		gotTenant    string
		gotAnthropic string
		gotAuth      string
		gotXDC       string
		gotXDefclaw  string
		gotHits      int32
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&gotHits, 1)
		gotTenant = r.Header.Get("Tenant-Id")
		gotAnthropic = r.Header.Get("Anthropic-Version")
		gotAuth = r.Header.Get("Authorization")
		gotXDC = r.Header.Get("X-DC-Target-URL")
		gotXDefclaw = r.Header.Get("X-DefenseClaw-Policy")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"resp_y","object":"response"}`))
	}))
	defer upstream.Close()

	proxy := newForwardingProxy(t, upstream.URL)
	body := mustJSON(t, map[string]interface{}{"model": "gpt-4.1", "input": "hi"})
	rec := postPassthrough(t, proxy, upstream.URL, "/v1/responses", map[string]string{
		"Tenant-Id":            "tenant-42",
		"Anthropic-Version":    "2023-06-01",
		"X-DC-Session-Id":      "internal-should-not-leak",
		"X-DefenseClaw-Policy": "should-not-leak",
	}, body)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if atomic.LoadInt32(&gotHits) != 1 {
		t.Fatalf("expected 1 upstream call, got %d", atomic.LoadInt32(&gotHits))
	}
	if gotTenant != "tenant-42" {
		t.Errorf("Tenant-Id = %q; want tenant-42", gotTenant)
	}
	if gotAnthropic != "2023-06-01" {
		t.Errorf("Anthropic-Version = %q; want 2023-06-01", gotAnthropic)
	}
	if !strings.Contains(gotAuth, "sk-upstream") {
		t.Errorf("Authorization should carry upstream key sk-upstream; got %q", gotAuth)
	}
	if gotXDC != "" {
		t.Errorf("X-DC-Target-URL leaked to upstream: %q", gotXDC)
	}
	if gotXDefclaw != "" {
		t.Errorf("X-DefenseClaw-Policy leaked to upstream: %q", gotXDefclaw)
	}
}

// TestPassthrough_ForwardCustomHeaders_Disabled verifies that
// llm.forward_custom_headers: false suppresses all inbound header
// copying.
func TestPassthrough_ForwardCustomHeaders_Disabled(t *testing.T) {
	var gotTenant, gotAnthropic, gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTenant = r.Header.Get("Tenant-Id")
		gotAnthropic = r.Header.Get("Anthropic-Version")
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer upstream.Close()

	proxy := newForwardingProxy(t, upstream.URL)
	proxy.cfg.LLM.ForwardCustomHeaders = boolPtr(false)

	body := mustJSON(t, map[string]interface{}{"model": "gpt-4.1", "input": "hi"})
	rec := postPassthrough(t, proxy, upstream.URL, "/v1/responses", map[string]string{
		"Tenant-Id":         "should-not-forward",
		"Anthropic-Version": "2023-06-01",
	}, body)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if gotTenant != "" {
		t.Errorf("Tenant-Id forwarded with toggle off: %q", gotTenant)
	}
	if gotAnthropic != "" {
		t.Errorf("Anthropic-Version forwarded with toggle off: %q", gotAnthropic)
	}
	if !strings.Contains(gotAuth, "sk-upstream") {
		t.Errorf("Authorization should still be re-minted; got %q", gotAuth)
	}
}

// TestPassthrough_HeaderInjection400 verifies CR/LF in a forwarded
// header value triggers HTTP 400 and the request does not reach the
// upstream.
func TestPassthrough_HeaderInjection400(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("upstream should not be reached on header injection")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer upstream.Close()

	proxy := newForwardingProxy(t, upstream.URL)
	body := mustJSON(t, map[string]interface{}{"model": "gpt-4.1", "input": "hi"})
	rec := postPassthrough(t, proxy, upstream.URL, "/v1/responses", map[string]string{
		"X-Evil": "value\r\nInjected-Header: leaked",
	}, body)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 on header injection; got %d: %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Chat-completions tests
// ---------------------------------------------------------------------------

// ctxRecordingProvider captures the ctx of each provider call so tests
// can assert what the gateway put on it (specifically the Bifrost
// extra-headers map).
type ctxRecordingProvider struct {
	mu      sync.Mutex
	lastCtx context.Context
}

func (p *ctxRecordingProvider) ChatCompletion(ctx context.Context, req *ChatRequest) (*ChatResponse, error) {
	p.mu.Lock()
	p.lastCtx = ctx
	p.mu.Unlock()
	return &ChatResponse{
		ID:     "chatcmpl-ctx",
		Object: "chat.completion",
		Model:  req.Model,
		Choices: []ChatChoice{{
			Index:        0,
			Message:      &ChatMessage{Role: "assistant", Content: "ok"},
			FinishReason: strPtr("stop"),
		}},
	}, nil
}

func (p *ctxRecordingProvider) ChatCompletionStream(ctx context.Context, _ *ChatRequest, _ func(StreamChunk)) (*ChatUsage, error) {
	p.mu.Lock()
	p.lastCtx = ctx
	p.mu.Unlock()
	return &ChatUsage{}, nil
}

// TestChatCompletions_ForwardsHeadersOnBifrostContext verifies that
// inbound headers (minus the blocklist) end up on the request context
// under schemas.BifrostContextKeyExtraHeaders so every Bifrost
// provider injects them onto the upstream HTTP request via
// providers/utils/utils.go:SetExtraHeaders.
func TestChatCompletions_ForwardsHeadersOnBifrostContext(t *testing.T) {
	prov := &ctxRecordingProvider{}
	insp := newMockInspector()
	proxy := newTestProxy(t, prov, insp, "action")

	body := mustJSON(t, map[string]interface{}{
		"model":    "gpt-4",
		"messages": []map[string]interface{}{{"role": "user", "content": "hi"}},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Anthropic-Version", "2023-06-01")
	req.Header.Set("Tenant-Id", "t-77")
	req.Header.Set("Authorization", "Bearer should-not-leak")
	req.Header.Set("X-DC-Session-Id", "should-not-leak")
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()

	proxy.handleChatCompletion(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	prov.mu.Lock()
	ctx := prov.lastCtx
	prov.mu.Unlock()
	if ctx == nil {
		t.Fatal("provider was not called")
	}
	raw := ctx.Value(schemas.BifrostContextKeyExtraHeaders)
	got, ok := raw.(map[string][]string)
	if !ok {
		t.Fatalf("BifrostContextKeyExtraHeaders missing or wrong type: %T %v", raw, raw)
	}
	if v := got["Anthropic-Version"]; len(v) != 1 || v[0] != "2023-06-01" {
		t.Errorf("Anthropic-Version on Bifrost ctx = %v; want [2023-06-01]", v)
	}
	if v := got["Tenant-Id"]; len(v) != 1 || v[0] != "t-77" {
		t.Errorf("Tenant-Id on Bifrost ctx = %v; want [t-77]", v)
	}
	for _, banned := range []string{"Authorization", "X-Dc-Session-Id"} {
		if v, present := got[banned]; present {
			t.Errorf("blocklisted header %q leaked onto Bifrost ctx: %v", banned, v)
		}
	}
}

// TestChatCompletions_ForwardCustomHeaders_Disabled verifies that
// llm.forward_custom_headers: false suppresses the Bifrost context
// key entirely (so the SDK has no headers to inject).
func TestChatCompletions_ForwardCustomHeaders_Disabled(t *testing.T) {
	prov := &ctxRecordingProvider{}
	insp := newMockInspector()
	proxy := newTestProxy(t, prov, insp, "action")
	proxy.cfg.LLM.ForwardCustomHeaders = boolPtr(false)

	body := mustJSON(t, map[string]interface{}{
		"model":    "gpt-4",
		"messages": []map[string]interface{}{{"role": "user", "content": "hi"}},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Tenant-Id", "should-not-forward")
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()

	proxy.handleChatCompletion(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	prov.mu.Lock()
	ctx := prov.lastCtx
	prov.mu.Unlock()
	if ctx == nil {
		t.Fatal("provider was not called")
	}
	if raw := ctx.Value(schemas.BifrostContextKeyExtraHeaders); raw != nil {
		t.Errorf("toggle disabled: BifrostContextKeyExtraHeaders should be nil; got %v", raw)
	}
}

// TestForwardCustomHeadersEnabled_Defaults exercises the *bool helper
// directly to guarantee "nil = true" semantics survive any refactor.
func TestForwardCustomHeadersEnabled_Defaults(t *testing.T) {
	cases := []struct {
		name string
		val  *bool
		want bool
	}{
		{"nil_defaults_true", nil, true},
		{"explicit_true", boolPtr(true), true},
		{"explicit_false", boolPtr(false), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := config.LLMConfig{ForwardCustomHeaders: tc.val}
			if got := c.ForwardCustomHeadersEnabled(); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
