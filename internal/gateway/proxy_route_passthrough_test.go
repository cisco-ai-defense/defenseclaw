// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestPassthroughAPIFamily(t *testing.T) {
	for path, want := range map[string]string{
		"/v1/messages":                          "messages",
		"/v1/messages/count_tokens":             "",
		"/v1/responses":                         "responses",
		"/v1/responses/compact":                 "",
		"/backend-api/codex/responses":          "responses",
		"/model/anthropic.claude-v2/invoke":     "invoke",
		"/model/x/invoke-with-response-stream":  "invoke",
		"/model/x/converse-stream":              "converse",
		"/v1beta/models/gemini:generateContent": "",
	} {
		if got := passthroughAPIFamily(path); got != want {
			t.Errorf("passthroughAPIFamily(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestSwapBedrockPathModelKeepsEscapedSegments(t *testing.T) {
	u, _ := url.Parse("https://bedrock-runtime.us-east-1.amazonaws.com/model/arn%3Aaws%3Abedrock%3Aus-east-1%3A1%3Ainference-profile%2Fus.anthropic.claude-sonnet/invoke?x=1")
	got := swapBedrockPathModel(u, "arn:aws:bedrock:us-east-1:1:inference-profile/us.anthropic.claude-haiku")
	want := "/model/arn:aws:bedrock:us-east-1:1:inference-profile%2Fus.anthropic.claude-haiku/invoke?x=1"
	if got != want {
		t.Fatalf("swap = %q, want %q", got, want)
	}
}

func TestPassthroughRoutesResponsesToSelectedBackend(t *testing.T) {
	var originalHits, routedHits int32
	var routedModel, routedAuth, routedTenant string
	original := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&originalHits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"resp_o","object":"response"}`))
	}))
	defer original.Close()
	routed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&routedHits, 1)
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		routedModel, _ = body["model"].(string)
		routedAuth = r.Header.Get("Authorization")
		routedTenant = r.Header.Get("Tenant-Id")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"resp_r","object":"response"}`))
	}))
	defer routed.Close()

	t.Setenv("ROUTING_PASSTHROUGH_TEST_KEY_8812", "k-routed")
	cfg := &config.Config{}
	cfg.Routing = config.RoutingConfig{
		Enabled: true, Classifier: config.RoutingClassifierRules,
		Models:    []config.RoutingModelBackend{{Name: "mini", Provider: "openai", Model: "gpt-4.1-mini", BaseURL: routed.URL, APIKeyEnv: "ROUTING_PASSTHROUGH_TEST_KEY_8812"}},
		Signals:   config.RoutingSignalConfig{Keywords: []config.RoutingKeywordSignal{{Name: "code", Keywords: []string{"refactor"}}}},
		Decisions: []config.RoutingDecisionRule{{Name: "code", Conditions: []config.RoutingCondition{{Type: "keyword", Name: "code"}}, ModelRefs: []string{"mini"}}},
	}
	if err := cfg.Routing.Validate(); err != nil {
		t.Fatal(err)
	}
	proxy := newForwardingProxy(t, original.URL)
	proxy.SetModelRouter(newEngineRouter(cfg, nil, ""))

	body := mustJSON(t, map[string]any{"model": "gpt-4.1", "input": "please refactor this"})
	rec := postPassthrough(t, proxy, original.URL, "/v1/responses", map[string]string{"Tenant-Id": "t-1"}, body)
	if rec.Code != http.StatusOK || rec.Header().Get("X-Semantic-Router") != "routed" {
		t.Fatalf("routed response %d %q: %s", rec.Code, rec.Header().Get("X-Semantic-Router"), rec.Body.String())
	}
	if atomic.LoadInt32(&routedHits) != 1 || atomic.LoadInt32(&originalHits) != 0 {
		t.Fatalf("hits routed=%d original=%d", routedHits, originalHits)
	}
	if routedModel != "gpt-4.1-mini" || routedAuth != "Bearer k-routed" {
		t.Fatalf("routed model=%q auth=%q", routedModel, routedAuth)
	}
	if routedTenant != "" {
		t.Fatal("custom agent headers crossed the routed credential boundary")
	}

	body = mustJSON(t, map[string]any{"model": "gpt-4.1", "input": "hello"})
	rec = postPassthrough(t, proxy, original.URL, "/v1/responses", nil, body)
	if rec.Code != http.StatusOK || atomic.LoadInt32(&originalHits) != 1 {
		t.Fatalf("unrouted request: %d hits=%d", rec.Code, originalHits)
	}

	body = mustJSON(t, map[string]any{"model": "gpt-4.1", "input": "refactor", "previous_response_id": "resp_1"})
	rec = postPassthrough(t, proxy, original.URL, "/v1/responses", nil, body)
	if rec.Code != http.StatusOK || atomic.LoadInt32(&routedHits) != 2 {
		t.Fatalf("same-provider stateful request should still route: %d routed=%d", rec.Code, routedHits)
	}
}
