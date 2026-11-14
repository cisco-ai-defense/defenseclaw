// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/routing/engine"
)

// rel-1-0-10 GAP-0003: the decision-model sensitivity check, end to end
// through the router (floor OR check; unavailable routes local).

func sensitiveCheckServer(t *testing.T, answer string, status int, calls *int32, seen *string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(calls, 1)
		var req struct {
			State     map[string]any            `json:"state"`
			Questions map[string]map[string]any `json:"questions"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if seen != nil {
			if s, ok := req.State["text"].(string); ok {
				*seen = s
			}
		}
		if _, ok := req.Questions["sensitive"]; !ok {
			t.Error("no sensitive question")
		}
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"answers": map[string]any{
			"sensitive": map[string]any{"type": "choice", "choice": answer, "probabilities": map[string]float64{answer: 0.9}},
		}})
	}))
}

func sensitiveCheckConfig(endpoint string) *config.Config {
	cfg := &config.Config{}
	cfg.DecisionModel.Enabled, cfg.DecisionModel.BaseURL, cfg.DecisionModel.Model = true, endpoint, "s1"
	cfg.Routing = config.RoutingConfig{
		Enabled: true, Classifier: config.RoutingClassifierRules,
		Models: []config.RoutingModelBackend{
			{Name: "local", Provider: "ollama", Model: "llama3.1", BaseURL: "http://127.0.0.1:11434"},
			{Name: "paid", Provider: "openai", Model: "gpt-4.1-mini"},
		},
		Decisions: []config.RoutingDecisionRule{{Name: "default", ModelRefs: []string{"paid"}}},
		Sensitive: &config.RoutingSensitiveConfig{Check: config.RoutingSensitiveCheckDecisionModel, Aliases: []string{"local"}, TimeoutMs: 500},
	}
	return cfg
}

func routeSensitive(t *testing.T, cfg *config.Config, text string) SemanticRouteOutcome {
	t.Helper()
	if err := cfg.Routing.Validate(); err != nil {
		t.Fatal(err)
	}
	r := newEngineRouter(cfg, nil, "")
	return r.RouteDetailed(context.Background(), &ModelRouterInput{Model: "gpt-5", RequestedProvider: "openai",
		Messages: []ChatMessage{{Role: "system", Content: "SYSTEM-PROMPT-NOT-SENT"}, {Role: "user", Content: text}}})
}

func TestSensitiveCheckPositiveKeepsTheRequestLocal(t *testing.T) {
	var calls int32
	var seen string
	srv := sensitiveCheckServer(t, "yes", http.StatusOK, &calls, &seen)
	defer srv.Close()
	out := routeSensitive(t, sensitiveCheckConfig(srv.URL+"/v1/systemone"), "the patient was diagnosed with x")
	if out.Result != SemanticRouteApplied || out.Route.Backend == nil || out.Route.Backend.Alias != "local" || out.Route.Sensitive.Source != "decision_model" {
		t.Fatalf("positive check: %+v %+v", out.Route, out.Route.Sensitive)
	}
	if calls != 1 || !strings.Contains(seen, "diagnosed") || strings.Contains(seen, "SYSTEM-PROMPT-NOT-SENT") {
		t.Fatalf("calls=%d text sent=%q", calls, seen)
	}
}

func TestSensitiveCheckNoKeepsTheRoute(t *testing.T) {
	var calls int32
	srv := sensitiveCheckServer(t, "no", http.StatusOK, &calls, nil)
	defer srv.Close()
	out := routeSensitive(t, sensitiveCheckConfig(srv.URL+"/v1/systemone"), "refactor this loop")
	if out.Route.Backend == nil || out.Route.Backend.Alias != "paid" || out.Route.SensitiveNarrowed() {
		t.Fatalf("negative check: %+v", out.Route)
	}
}

func TestSensitiveCheckUnavailableRoutesLocalNeverBlocks(t *testing.T) {
	for name, status := range map[string]int{"5xx": http.StatusBadGateway, "garbage": http.StatusOK} {
		var calls int32
		srv := sensitiveCheckServer(t, "maybe", status, &calls, nil)
		out := routeSensitive(t, sensitiveCheckConfig(srv.URL+"/v1/systemone"), "anything")
		srv.Close()
		if out.Result == SemanticRouteDenied || out.Route.Backend == nil || out.Route.Backend.Alias != "local" || out.Route.Sensitive.CheckFailure == "" {
			t.Fatalf("%s: %+v %+v", name, out.Route, out.Route.Sensitive)
		}
	}
}

func TestSensitiveCheckOffAsksNothing(t *testing.T) {
	var calls int32
	srv := sensitiveCheckServer(t, "yes", http.StatusOK, &calls, nil)
	defer srv.Close()
	cfg := sensitiveCheckConfig(srv.URL + "/v1/systemone")
	cfg.Routing.Sensitive.Check = config.RoutingSensitiveCheckOff
	cfg.Routing.Sensitive.Signals = []string{"none-such"}
	cfg.Routing.Signals = config.RoutingSignalConfig{Keywords: []config.RoutingKeywordSignal{{Name: "none-such", Keywords: []string{"zzqx"}}}}
	if out := routeSensitive(t, cfg, "the patient was diagnosed"); calls != 0 || out.Route.SensitiveNarrowed() {
		t.Fatalf("check off asked %d times: %+v", calls, out.Route)
	}
}

func TestSensitiveCheckInputIsBounded(t *testing.T) {
	text, cut := sensitiveCheckInput(&ModelRouterInput{Messages: []ChatMessage{
		{Role: "system", Content: "never"}, {Role: "user", Content: strings.Repeat("a", 600)}, {Role: "user", Content: "newest"},
	}}, 256)
	if !cut || len(text) > 256 || !strings.HasPrefix(text, "newest") || strings.Contains(text, "never") {
		t.Fatalf("bounded input %q cut=%v", text, cut)
	}
	if _, cut := sensitiveCheckInput(&ModelRouterInput{Text: "short"}, 256); cut {
		t.Fatal("a short text is not cut")
	}
	_ = engine.SensitiveInput{}
}
