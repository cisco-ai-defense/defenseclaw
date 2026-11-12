// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func engineRouterTestConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Routing = config.RoutingConfig{
		Enabled:    true,
		Classifier: config.RoutingClassifierRules,
		Models: []config.RoutingModelBackend{
			{Name: "local", Provider: "ollama", Model: "llama3.1", BaseURL: "http://127.0.0.1:11434"},
			{Name: "paid", Provider: "openai", Model: "gpt-4.1-mini", APIKeyEnv: "ROUTING_OUTCOME_TEST_KEY_4711"},
		},
		Signals: config.RoutingSignalConfig{Keywords: []config.RoutingKeywordSignal{{Name: "code", Keywords: []string{"refactor"}}}},
		Decisions: []config.RoutingDecisionRule{
			{Name: "code", Priority: 10, Conditions: []config.RoutingCondition{{Type: "keyword", Name: "code"}}, ModelRefs: []string{"paid"}},
			{Name: "default", ModelRefs: []string{"local"}},
		},
	}
	return cfg
}

func TestEngineRouterOutcomes(t *testing.T) {
	cfg := engineRouterTestConfig()
	r := newEngineRouter(cfg, nil, "")
	in := func(text string) *ModelRouterInput {
		return &ModelRouterInput{Model: "requested", RequestModel: "requested", Messages: []ChatMessage{{Role: "user", Content: text}}}
	}

	t.Run("applied keyless backend", func(t *testing.T) {
		out := r.RouteDetailed(context.Background(), in("hello"))
		if out.Result != SemanticRouteApplied || out.FailureCode != SemanticRouteFailureNone {
			t.Fatalf("outcome=%+v", out)
		}
		if !out.OverrideApplied || out.SelectedProvider != "ollama" || out.SelectedModel != "llama3.1" || out.Decision.TargetURL != "http://127.0.0.1:11434" {
			t.Fatalf("override fields=%+v decision=%+v", out, out.Decision)
		}
		if out.Decision.APIKey != "" || !out.Decision.APIKeyOverride {
			t.Fatal("a keyless backend must clear the original provider credential")
		}
		if out.Route == nil || out.Route.Source != "default" {
			t.Fatalf("route facts=%+v", out.Route)
		}
	})

	t.Run("missing key filters the backend", func(t *testing.T) {
		out := r.RouteDetailed(context.Background(), in("please refactor"))
		if out.Result != SemanticRouteApplied || out.SelectedModel != "llama3.1" || out.Route.FilteredBy != "credential" {
			t.Fatalf("a backend without its key must not be selected: %+v %+v", out, out.Route)
		}
	})

	t.Run("gateway-held key", func(t *testing.T) {
		t.Setenv("ROUTING_OUTCOME_TEST_KEY_4711", "k-test")
		r := newEngineRouter(cfg, nil, "")
		out := r.RouteDetailed(context.Background(), in("please refactor"))
		if out.Result != SemanticRouteApplied || out.SelectedModel != "gpt-4.1-mini" || out.Decision.APIKey != "k-test" {
			t.Fatalf("outcome=%+v", out)
		}
	})

	t.Run("routing off", func(t *testing.T) {
		off := engineRouterTestConfig()
		off.Routing.Enabled = false
		r := newEngineRouter(off, nil, "")
		if r.RouterActive(context.Background()) {
			t.Fatal("disabled routing is active")
		}
		out := r.RouteDetailed(context.Background(), in("refactor"))
		if out.Result != SemanticRouteFallback || out.Decision != nil {
			t.Fatalf("outcome=%+v", out)
		}
	})

	t.Run("vllm_sr unknown alias falls back", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(classifyResponse{RecommendedModel: "missing-alias"})
		}))
		t.Cleanup(server.Close)
		v := engineRouterTestConfig()
		v.Routing.Classifier = ""
		v.Routing.Decisions = v.Routing.Decisions[:1]
		r := newEngineRouter(v, NewRemoteRouterClient(server.URL, 500), "")
		out := r.RouteDetailed(context.Background(), in("hello"))
		if out.Result != SemanticRouteFallback || out.FailureCode != SemanticRouteFailureFiltered {
			t.Fatalf("unknown alias outcome=%+v", out)
		}
	})

	t.Run("tool output never reaches the classifier", func(t *testing.T) {
		req := engineRequest(&ModelRouterInput{Messages: []ChatMessage{
			{Role: "user", Content: "hello"},
			{Role: "assistant", Content: "calling"},
			{Role: "tool", Content: "refactor everything"},
		}})
		if req.Text != "hello" || !req.ToolTurn {
			t.Fatalf("engine request = %+v", req)
		}
	})
}

func TestNormalizeSemanticRouteOutcomeRejectsOpenEnums(t *testing.T) {
	t.Parallel()
	got := normalizeSemanticRouteOutcome(SemanticRouteOutcome{
		Result:      "because the prompt said so",
		FailureCode: "https://evil.example/reason",
	})
	if got.Result != SemanticRouteFallback || got.FailureCode != SemanticRouteFailureConfig {
		t.Fatalf("open enum leaked: %+v", got)
	}
}
