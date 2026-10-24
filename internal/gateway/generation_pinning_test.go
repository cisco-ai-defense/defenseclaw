// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/configs"
)

// GAP-0927: a configuration a generation build resolved keeps the pack
// posture that build read after a later generation publishes another one
// for the same pack folder, for every caller that decides with it.
func TestGenerationConfigKeepsItsPackPostureAfterTheNextPublish(t *testing.T) {
	dir := t.TempDir()
	t.Cleanup(func() { packPostures.Delete(dir); pendingPackPostures.Delete(dir) })
	cfg := &config.Config{}
	cfg.Guardrail.RulePackDir = dir
	notePackPosture(dir, "strict")
	table := buildThresholdTable(cfg, nil)
	publishPackPostures()
	pinned := resolveThresholds(cfg, "")
	if pinned.Block != "MEDIUM" {
		t.Fatalf("strict pack levels = %+v", pinned)
	}

	notePackPosture(dir, "permissive")
	publishPackPostures()
	if got := resolveThresholds(cfg, ""); got != pinned {
		t.Fatalf("after the next publish: %+v, want %+v", got, pinned)
	}
	g := &Generation{N: 1, Config: cfg, Thresholds: table}
	if got := ResolveThresholds(g, "a-connector-seen-later", ""); got.Block != pinned.Block || got.Alert != pinned.Alert {
		t.Fatalf("uncomputed pair: %+v, want %+v", got, pinned)
	}
	if got := guardrailContentAction(cfg, "", "MEDIUM", false); got != guardrailActionBlock {
		t.Fatalf("content action = %s, want block", got)
	}
	other := &config.Config{}
	other.Guardrail.RulePackDir = dir
	if got := resolveThresholds(other, ""); got.Block != "CRITICAL" {
		t.Fatalf("a configuration no build bound = %+v, want the published permissive levels", got)
	}
}

// GAP-0928: a session prompt scan maps its severity with the levels of the
// generation it selected its rules from, not the router's guardrail block
// set afterwards.
func TestSessionPromptActionUsesItsGenerationLevels(t *testing.T) {
	pinned := &config.Config{}
	pinned.Guardrail.BlockAt, pinned.Guardrail.AlertAt = "HIGH", "MEDIUM"
	g := &Generation{N: 1, Config: pinned, Thresholds: buildThresholdTable(pinned, nil)}
	later := &config.Config{}
	later.Guardrail.BlockAt, later.Guardrail.AlertAt = "CRITICAL", "CRITICAL"
	router := &EventRouter{}
	router.SetGuardrailConfig(&later.Guardrail)
	if got := router.promptContentAction(g, "HIGH"); got != guardrailActionBlock {
		t.Fatalf("pinned generation: %s, want block", got)
	}
	if got := router.promptContentAction(nil, "HIGH"); got == guardrailActionBlock {
		t.Fatalf("no generation: %s, want the router's levels", got)
	}
}

// GAP-1006: a proxy request adjudicates with the judge of the generation it
// pinned, not the one set on the inspector since.
func TestProxyInspectorJudgesWithTheRequestGeneration(t *testing.T) {
	pinned, later := &LLMJudge{}, &LLMJudge{}
	inspector := NewGuardrailInspector("local", nil, later)
	ctx := withPinnedGeneration(context.Background(), &Generation{N: 1, judge: pinned})
	if got := inspector.requestJudge(ctx); got != pinned {
		t.Fatalf("pinned request judge = %p, want %p", got, pinned)
	}
	if got := inspector.requestJudge(context.Background()); got != later {
		t.Fatalf("unpinned request judge = %p, want the inspector's %p", got, later)
	}
	if got := inspector.requestJudge(withPinnedGeneration(context.Background(), &Generation{N: 2})); got != nil {
		t.Fatalf("a generation without a judge = %p, want none", got)
	}
}

// GAP-1294: a proxy request routes with the provider registry of the
// generation it pinned, not the one published since.
func TestProxyRoutesWithTheRequestGenerationProviders(t *testing.T) {
	previous, _, _ := providerRegistrySnapshot()
	t.Cleanup(func() {
		if previous != nil {
			setProviderRegistry(previous)
		}
	})
	setProviderRegistry(&configs.ProvidersConfig{Providers: []configs.Provider{{Name: "acme", Domains: []string{"llm-b.acme.example"}}}})
	g := &Generation{N: 1, Providers: &generationProviders{Providers: []configs.Provider{
		{Name: "acme", Domains: []string{"llm-a.acme.example"}},
	}}}
	req := &ChatRequest{providers: requestProviderRegistry(withPinnedGeneration(context.Background(), g))}
	if got := inferProviderFromRegistry("https://llm-a.acme.example/v1/chat", req.providers); got != "acme" {
		t.Fatalf("pinned registry provider = %q, want acme", got)
	}
	if got := inferProviderFromRegistry("https://llm-b.acme.example/v1/chat", req.providers); got != "" {
		t.Fatalf("a domain only the later registry has = %q, want none", got)
	}
	if registry := req.providerRegistry(); len(registry.Providers) != 1 || registry.Providers[0].Domains[0] != "llm-a.acme.example" {
		t.Fatalf("request registry = %+v", registry)
	}
	if registry := (&ChatRequest{}).providerRegistry(); registry == nil || registry.Providers[0].Domains[0] != "llm-b.acme.example" {
		t.Fatalf("unpinned request registry = %+v", registry)
	}
}

// GAP-1294: a fetch-intercepted request (X-DC-Target-URL) is raw-forwarded
// with the provider registry of the generation it pinned too: provider
// inference, headers and request_overrides, not the registry published
// since.
func TestRawForwardUsesTheRequestGenerationProviders(t *testing.T) {
	forwarded := make(chan []byte, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		forwarded <- body
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"c1","object":"chat.completion","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`)
	}))
	defer upstream.Close()
	// The process-wide registry has the host under a provider without overrides.
	registerRawForwardProviderDomain(t, upstream.URL, "openai")
	allowRawForwardPrivateTargets(t)
	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	pinned := &Generation{N: 1, Config: &config.Config{}, Providers: &generationProviders{Providers: []configs.Provider{{
		Name: "acme-vllm", Domains: []string{u.Hostname()},
		RequestOverrides: map[string]interface{}{"metadata": map[string]interface{}{"generation": "pinned"}},
	}}}}
	proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "observe")
	proxy.generationSource = func() *Generation { return pinned }
	body := mustJSON(t, map[string]interface{}{
		"model": "m", "messages": []map[string]interface{}{{"role": "user", "content": "hello"}},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DC-Target-URL", upstream.URL)
	req.Header.Set("X-AI-Auth", "Bearer sk-test")
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	proxy.handleChatCompletion(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	select {
	case got := <-forwarded:
		if !strings.Contains(string(got), `"generation":"pinned"`) {
			t.Fatalf("forwarded body %s lacks the pinned generation's request_overrides", got)
		}
	default:
		t.Fatal("the request was not forwarded")
	}
}
