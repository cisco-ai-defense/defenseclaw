// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/routing/engine"
)

// rel-1-0-10:GAP-1167: a bedrock alias added with --api responses and no
// base_url was chosen for route-only Codex calls (routing test said applied
// -> oss), but the listener had no endpoint for it, so the real call fell
// back to the original model with only route_only_fallback:origin and no
// filtered_by reason. The engine now skips it for route-only calls with
// filtered_by endpoint, routing test decides a route-only connector as its
// listener does, and the same model behind the Bedrock OpenAI-compatible
// base_url still routes.
func TestRouteOnlyBedrockResponsesAliasWithoutBaseURLIsFilteredWithAReason(t *testing.T) {
	f := newRouteOnlyFixture(t)
	f.cfg.Routing.RouteOnly.Connectors = append(f.cfg.Routing.RouteOnly.Connectors, "codex")
	f.cfg.Routing.RouteOnly.Upstreams["codex"] = config.RoutingUpstreamConfig{BaseURL: f.orig.URL, API: config.RoutingAPIResponses}
	f.cfg.Routing.Models = append(f.cfg.Routing.Models,
		config.RoutingModelBackend{Name: "oss", Provider: "bedrock", Model: "openai.gpt-oss-120b-1:0", APIs: []string{config.RoutingAPIResponses}, APIKeyEnv: "ROUTE_ONLY_TEST_KEY_5511"},
		config.RoutingModelBackend{Name: "oai", Provider: "openai", Model: "openai.gpt-oss-120b-1:0", BaseURL: f.alt.URL + "/openai/v1", APIs: []string{config.RoutingAPIResponses}, APIKeyEnv: "ROUTE_ONLY_TEST_KEY_5511"},
	)
	f.cfg.Routing.Signals.Keywords = append(f.cfg.Routing.Signals.Keywords,
		config.RoutingKeywordSignal{Name: "coding", Keywords: []string{"refactor this"}},
		config.RoutingKeywordSignal{Name: "viaopenai", Keywords: []string{"compat endpoint"}})
	f.cfg.Routing.Decisions = append([]config.RoutingDecisionRule{
		{Name: "coding", Priority: 20, Conditions: []config.RoutingCondition{{Type: "keyword", Name: "coding"}}, ModelRefs: []string{"oss"}},
		{Name: "viaopenai", Priority: 10, Conditions: []config.RoutingCondition{{Type: "keyword", Name: "viaopenai"}}, ModelRefs: []string{"oai"}},
	}, f.cfg.Routing.Decisions...)
	if err := f.cfg.Routing.Validate(); err != nil {
		t.Fatal(err)
	}

	decide := func(t *testing.T, prompt string) SemanticRouteOutcome {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "/r/codex/v1/responses", nil)
		caller, profiles := routeOnlyCaller(r.Context(), "owner")
		body := []byte(`{"model":"us.openai.gpt-5.6-luna","input":"` + prompt + `"}`)
		_, out, _ := f.srv.decide(r, f.cfg, "codex", "/v1/responses", config.RoutingAPIResponses, f.cfg.Routing.RouteOnly.Upstreams["codex"], engine.CredentialAPIKey, nil, body, caller, profiles)
		return out
	}

	out := decide(t, "please refactor this function")
	if out.Route == nil || out.Result != SemanticRouteFallback {
		t.Fatalf("the bedrock responses alias cannot serve the call: %+v", out)
	}
	if out.Route.FilteredBy != "endpoint" || out.Route.Candidate != "oss" {
		t.Fatalf("explain must name the candidate and why it was skipped: candidate %q filtered_by %q", out.Route.Candidate, out.Route.FilteredBy)
	}
	if slices.Contains(out.Route.Warnings, "route_only_fallback:origin") {
		t.Fatalf("the engine skips the alias; the call is not prepared for it and then dropped: %v", out.Route.Warnings)
	}

	// The same model behind the Bedrock OpenAI-compatible base_url routes.
	viaOpenAI := decide(t, "use the compat endpoint please")
	if viaOpenAI.Result != SemanticRouteApplied || viaOpenAI.Route == nil || viaOpenAI.Route.Backend == nil || viaOpenAI.Route.Backend.Alias != "oai" {
		t.Fatalf("openai alias with a base_url: %+v", viaOpenAI)
	}

	// routing test as codex agrees with the real call.
	previous := activeEngineRouter.Load()
	activeEngineRouter.Store(f.srv.router)
	t.Cleanup(func() { activeEngineRouter.Store(previous) })
	routingTestLimiter.Lock()
	previousLast := routingTestLimiter.last
	routingTestLimiter.last = map[string]time.Time{}
	routingTestLimiter.Unlock()
	t.Cleanup(func() {
		routingTestLimiter.Lock()
		routingTestLimiter.last = previousLast
		routingTestLimiter.Unlock()
	})
	a := &APIServer{scannerCfg: f.cfg}
	rec := httptest.NewRecorder()
	a.handleRoutingTest(rec, httptest.NewRequest(http.MethodPost, "/api/v1/routing/test", strings.NewReader(`{"prompt":"please refactor this function","connector":"codex"}`)))
	var answer struct {
		Outcome   string   `json:"outcome"`
		Candidate string   `json:"candidate_alias"`
		Filtered  string   `json:"filtered_by"`
		Selected  string   `json:"selected_alias"`
		Simulated []string `json:"simulated"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &answer); rec.Code != http.StatusOK || err != nil {
		t.Fatalf("routing test: %d %s", rec.Code, rec.Body.String())
	}
	if answer.Outcome != engine.OutcomeFallback || answer.Candidate != "oss" || answer.Filtered != "endpoint" || answer.Selected != "" {
		t.Fatalf("routing test as codex must agree with the real call: %s", rec.Body.String())
	}
	if len(answer.Simulated) == 0 || !strings.Contains(answer.Simulated[0], "route-only responses") {
		t.Fatalf("routing test says it decided as the route-only listener: %v", answer.Simulated)
	}
}
