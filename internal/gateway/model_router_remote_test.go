// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRemoteRouterClientRouteUsesBoundedV03Contract(t *testing.T) {
	var received map[string]json.RawMessage
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/classify/intent" || r.Method != http.MethodPost {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(classifyResponse{
			RecommendedModel: "fast",
			RoutingDecision:  "keyword",
			Classification:   classifyClassification{Confidence: 0.95},
		})
	}))
	defer srv.Close()

	client := NewRemoteRouterClient(srv.URL+"/", 100)
	decision := client.Route(context.Background(), &ModelRouterInput{
		Model: "auto", RequestModel: "requested", Stream: true,
		Messages:   []ChatMessage{{Role: "user", Content: "debug this"}},
		Tools:      []interface{}{map[string]interface{}{"type": "function"}},
		SessionID:  "session-1",
		UserID:     "user-1",
		UserGroups: []string{"engineering"},
		Metadata:   map[string]interface{}{"guardrail_severity": "LOW"},
	})
	if decision == nil || decision.Model != "fast" || decision.Reason == "" {
		t.Fatalf("decision = %+v", decision)
	}
	if len(received) != 2 || received["messages"] == nil || received["options"] == nil {
		t.Fatalf("classifier received unsupported gateway context: keys=%v", received)
	}
	var messages []classifyMessage
	if err := json.Unmarshal(received["messages"], &messages); err != nil || len(messages) != 1 || messages[0].Content != "debug this" {
		t.Fatalf("classify messages = %+v, err=%v", messages, err)
	}
}

func TestRemoteRouterClientGracefulFallbacks(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		client := NewRemoteRouterClient("http://127.0.0.1:1", 10)
		if got := client.Route(context.Background(), nil); got != nil {
			t.Fatalf("decision = %+v", got)
		}
	})
	t.Run("empty endpoint", func(t *testing.T) {
		if got := NewRemoteRouterClient("", 10).Route(context.Background(), &ModelRouterInput{}); got != nil {
			t.Fatalf("decision = %+v", got)
		}
	})
	t.Run("unreachable", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		endpoint := srv.URL
		srv.Close()
		if got := NewRemoteRouterClient(endpoint, 10).Route(context.Background(), &ModelRouterInput{}); got != nil {
			t.Fatalf("decision = %+v", got)
		}
	})
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{name: "server error", status: http.StatusInternalServerError, body: `{"error":"failed"}`},
		{name: "bad json", status: http.StatusOK, body: `{bad`},
		{name: "empty alias", status: http.StatusOK, body: `{"recommended_model":""}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			if got := NewRemoteRouterClient(srv.URL, 100).Route(context.Background(), &ModelRouterInput{}); got != nil {
				t.Fatalf("decision = %+v", got)
			}
		})
	}
	t.Run("timeout", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(100 * time.Millisecond)
			_ = json.NewEncoder(w).Encode(classifyResponse{RecommendedModel: "fast"})
		}))
		defer srv.Close()
		if got := NewRemoteRouterClient(srv.URL, 5).Route(context.Background(), &ModelRouterInput{}); got != nil {
			t.Fatalf("decision = %+v", got)
		}
	})
}

func TestConfiguredRemoteRouterResolvesAliasAndClearsOriginalCredential(t *testing.T) {
	srv := routerResponseServer(t, "local-fast")
	defer srv.Close()
	client := NewConfiguredRemoteRouterClient(srv.URL, 100, []ModelRouterBackend{{
		Name: "local-fast", Provider: "ollama", Model: "qwen2.5:0.5b", BaseURL: "http://127.0.0.1:11434",
	}}, "")
	decision := client.Route(context.Background(), &ModelRouterInput{})
	if decision == nil || decision.Provider != "ollama" || decision.Model != "qwen2.5:0.5b" ||
		decision.TargetURL != "http://127.0.0.1:11434" || !decision.TargetURLOverride ||
		!decision.APIKeyOverride || decision.APIKey != "" {
		t.Fatalf("decision = %+v", decision)
	}
}

func TestConfiguredRemoteRouterRejectsUnknownAliasAndMissingCredential(t *testing.T) {
	srv := routerResponseServer(t, "unknown")
	client := NewConfiguredRemoteRouterClient(srv.URL, 100, []ModelRouterBackend{{Name: "known", Provider: "ollama", Model: "tiny"}}, "")
	if got := client.Route(context.Background(), &ModelRouterInput{}); got != nil {
		t.Fatalf("unknown alias decision = %+v", got)
	}
	srv.Close()

	srv = routerResponseServer(t, "paid")
	defer srv.Close()
	client = NewConfiguredRemoteRouterClient(srv.URL, 100, []ModelRouterBackend{{
		Name: "paid", Provider: "openai", Model: "gpt-4.1-mini", APIKeyEnv: "ROUTING_TEST_MISSING_KEY_9382",
	}}, "")
	if got := client.Route(context.Background(), &ModelRouterInput{}); got != nil {
		t.Fatalf("missing-credential decision = %+v", got)
	}
}

func TestConfiguredRemoteRouterUsesManagedTokenResolver(t *testing.T) {
	oldResolver := tokenResolver
	oldDisabled := localKeyResolutionDisabled
	t.Cleanup(func() {
		tokenResolver = oldResolver
		localKeyResolutionDisabled = oldDisabled
	})
	DisableLocalKeyResolution()
	SetTokenResolver(func(_ context.Context, provider string) (string, error) {
		if provider != "openai" {
			t.Fatalf("resolver provider = %q, want openai", provider)
		}
		return "managed-routing-token", nil
	})

	srv := routerResponseServer(t, "paid")
	defer srv.Close()
	client := NewConfiguredRemoteRouterClient(srv.URL, 100, []ModelRouterBackend{{
		Name: "paid", Provider: "openai", Model: "gpt-4.1-mini", APIKeyEnv: "OPENAI_API_KEY",
	}}, "")
	decision := client.Route(context.Background(), &ModelRouterInput{})
	if decision == nil || decision.APIKey != "managed-routing-token" || !decision.APIKeyOverride {
		t.Fatalf("managed decision = %+v", decision)
	}
}

func TestRemoteRouterClientDoesNotFollowRedirects(t *testing.T) {
	redirectTargetCalled := false
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirectTargetCalled = true }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	if got := NewRemoteRouterClient(source.URL, 100).Route(context.Background(), &ModelRouterInput{}); got != nil {
		t.Fatalf("redirect decision = %+v", got)
	}
	if redirectTargetCalled {
		t.Fatal("classifier prompt was sent to a redirect target")
	}
}

func TestRemoteRouterClientHealthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	if !NewRemoteRouterClient(srv.URL, 100).Healthy(context.Background()) {
		t.Fatal("expected healthy router")
	}
	if (*RemoteRouterClient)(nil).Healthy(context.Background()) {
		t.Fatal("nil client reported healthy")
	}
}

func TestRemoteRouterClientHealthBudgetDoesNotInheritClassificationTimeout(t *testing.T) {
	const responseDelay = 100 * time.Millisecond
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(responseDelay)
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(http.StatusOK)
		case "/api/v1/classify/intent":
			_ = json.NewEncoder(w).Encode(classifyResponse{RecommendedModel: "fast"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client := NewRemoteRouterClient(srv.URL, 50)
	if !client.Healthy(context.Background()) {
		t.Fatal("health response within the probe budget inherited the shorter classification timeout")
	}
	if got := client.Route(context.Background(), &ModelRouterInput{}); got != nil {
		t.Fatalf("classification exceeded its latency budget: decision = %+v", got)
	}
}

func routerResponseServer(t *testing.T, alias string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(classifyResponse{RecommendedModel: alias})
	}))
}
