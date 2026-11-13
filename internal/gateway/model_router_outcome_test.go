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
	"github.com/defenseclaw/defenseclaw/internal/routing/engine"
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

// DESIGN 4.6: no request header can make a caller verified or pick a
// profile overlay.
func TestRouteCallerIgnoresHeaders(t *testing.T) {
	caller, profiles := routeCallerFromContext(context.Background())
	if caller.Verified || caller.Key != "" || profiles != nil {
		t.Fatalf("caller from an unauthenticated context = %+v %v", caller, profiles)
	}
	in := &ModelRouterInput{Model: "m", Messages: []ChatMessage{{Role: "user", Content: "hi"}}}
	if req := engineRequest(in); req.Caller.Verified || len(req.Profiles) != 0 {
		t.Fatalf("engine request = %+v", req)
	}
}

func TestEngineRouterVLLMWithoutContainerIsInactive(t *testing.T) {
	cfg := engineRouterTestConfig()
	cfg.Routing.Classifier = ""
	cfg.Routing.Decisions = cfg.Routing.Decisions[:1]
	if newEngineRouter(cfg, nil, "").RouterActive(context.Background()) {
		t.Fatal("vllm_sr without a started container must leave routing off, as in 1.0.9")
	}
}

// Lead item 1: a 1.0.9 managed config names the routed key by api_key_env;
// after the upgrade the key still resolves on the managed host (doctor
// warns to move it to a protected credential).
func TestEngineRouterManagedAPIKeyEnvKeepsWorking(t *testing.T) {
	t.Setenv("ROUTING_MANAGED_LEGACY_KEY_7731", "k-legacy")
	cfg := engineRouterTestConfig()
	cfg.DeploymentMode = string(config.DeploymentModeManagedEnterprise)
	cfg.Enterprise.Profile = "standalone"
	if !cfg.StandaloneEnterprise() {
		t.Fatal("fixture is not standalone")
	}
	cfg.Routing.Models[1].APIKeyEnv = "ROUTING_MANAGED_LEGACY_KEY_7731"
	r := newEngineRouter(cfg, nil, "")
	b, _ := mustRouterEngine(t, r).Backend("paid")
	if got := r.backendKey(cfg, b); got != "k-legacy" {
		t.Fatalf("managed api_key_env key = %q", got)
	}
	// A named credential is the only source, even when it is missing.
	b.Credential = "missing-credential"
	if got := r.backendKey(cfg, b); got != "" {
		t.Fatalf("a model with a credential read the environment: %q", got)
	}
}

func mustRouterEngine(t *testing.T, r *engineRouter) *engine.Engine {
	t.Helper()
	eng, _ := r.engineFor(context.Background())
	if eng == nil {
		t.Fatal("no engine")
	}
	return eng
}
