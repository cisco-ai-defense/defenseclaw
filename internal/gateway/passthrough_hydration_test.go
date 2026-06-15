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
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// newDirectProviderProxy constructs a GuardrailProxy that exercises the
// passthrough direct-provider hydration path: no X-DC-Target-URL, no
// active connector, upstream resolved from cfg.LLM.BaseURL and the API
// key from an env var (mirrors the secrets-sidecar handoff).
func newDirectProviderProxy(t *testing.T, prov LLMProvider, insp ContentInspector, upstreamURL, apiKey string) *GuardrailProxy {
	t.Helper()
	// Use a unique env var per test so parallel tests don't collide.
	envName := "DEFENSECLAW_TEST_LLM_KEY_" + sanitizeForEnv(t.Name())
	t.Setenv(envName, apiKey)

	cfg := &config.GuardrailConfig{
		Enabled:   true,
		Model:     "openai/gpt-4",
		ModelName: "gpt-4",
		APIKeyEnv: envName,
		Port:      0,
		Mode:      "action",
		LLM: config.LLMConfig{
			Model:     "openai/gpt-4",
			APIKeyEnv: envName,
			BaseURL:   upstreamURL,
		},
	}
	store, logger := testStoreAndLogger(t)
	p := &GuardrailProxy{
		cfg:             cfg,
		logger:          logger,
		health:          NewSidecarHealth(),
		store:           store,
		dataDir:         t.TempDir(),
		inspector:       insp,
		mode:            "action",
		skipAuthForTest: true,
	}
	p.resolveProviderFn = func(_ *ChatRequest) LLMProvider { return prov }

	// The upstream URL host must pass isKnownProviderDomain, otherwise
	// the three-branch passthrough policy classifies it as "passthrough"
	// and blocks it. Inject the upstream host into providerDomains for
	// the duration of the test.
	u, err := url.Parse(upstreamURL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}
	registerProviderDomainForTest(t, u.Hostname(), "openai")
	return p
}

// registerProviderDomainForTest appends a (domain, provider) entry to
// the package-level providerDomains slice for the duration of the
// test, restoring the original list on cleanup.
func registerProviderDomainForTest(t *testing.T, domain, provider string) {
	t.Helper()
	orig := providerDomains
	providerDomains = append(append([]providerDomainEntry{}, orig...),
		providerDomainEntry{domain: domain, name: provider})
	t.Cleanup(func() { providerDomains = orig })
}

// sanitizeForEnv replaces characters disallowed in env-var names so a
// Go subtest name (which may contain '/', '_', spaces, etc.) can be
// safely used as an env var suffix.
func sanitizeForEnv(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_':
			b.WriteRune(r)
		case r >= 'a' && r <= 'z':
			b.WriteRune(r - 'a' + 'A')
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// TestHandlePassthrough_DirectProviderHydration verifies that a
// Responses-API request without X-DC-Target-URL or a connector-supplied
// upstream is hydrated from llm.base_url + APIKeyEnv and forwarded
// successfully. Mirrors the ZeptoClaw + custom-provider topology the
// gateway must support.
func TestHandlePassthrough_DirectProviderHydration(t *testing.T) {
	var (
		gotPath          string
		gotAuthorization string
		gotXDC           string
		gotForwardedHits int32
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&gotForwardedHits, 1)
		gotPath = r.URL.Path
		gotAuthorization = r.Header.Get("Authorization")
		// Internal correlation headers must never reach upstream.
		gotXDC = r.Header.Get("X-DC-Target-URL")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"resp_abc","object":"response","status":"completed"}`))
	}))
	defer upstream.Close()

	prov := &mockProvider{}
	insp := newMockInspector()
	proxy := newDirectProviderProxy(t, prov, insp, upstream.URL, "sk-test-upstream-key")

	body := mustJSON(t, map[string]interface{}{
		"model": "gpt-4.1",
		"input": "Hello from agent",
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// DefenseClaw correlation must not leak.
	req.Header.Set("X-DC-Target-URL", "")
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()

	proxy.handlePassthrough(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if atomic.LoadInt32(&gotForwardedHits) != 1 {
		t.Fatalf("expected exactly 1 upstream call, got %d", atomic.LoadInt32(&gotForwardedHits))
	}
	if gotPath != "/v1/responses" {
		t.Errorf("upstream path = %q, want /v1/responses", gotPath)
	}
	if !strings.HasPrefix(gotAuthorization, "Bearer ") || !strings.Contains(gotAuthorization, "sk-test-upstream-key") {
		t.Errorf("upstream Authorization = %q; want Bearer sk-test-upstream-key", gotAuthorization)
	}
	if gotXDC != "" {
		t.Errorf("upstream X-DC-Target-URL = %q; expected stripped", gotXDC)
	}
}

// TestHandlePassthrough_NoUpstream_400 verifies the new 400 message
// when the proxy can find no upstream from any source (no header, no
// connector, no llm.base_url).
func TestHandlePassthrough_NoUpstream_400(t *testing.T) {
	prov := &mockProvider{}
	insp := newMockInspector()
	proxy := newTestProxy(t, prov, insp, "action")
	// Explicitly clear llm.base_url so the new hydration fallback also
	// returns empty, exercising the final reject branch.
	proxy.cfg.LLM.BaseURL = ""

	body := mustJSON(t, map[string]interface{}{"model": "gpt-4.1", "input": "hi"})
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()

	proxy.handlePassthrough(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400; got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "llm.base_url") {
		t.Errorf("expected error message to mention llm.base_url; got %s", rec.Body.String())
	}
}
