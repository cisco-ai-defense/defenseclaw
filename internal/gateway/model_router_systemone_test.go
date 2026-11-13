// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/routing/engine"
)

func systemOneServer(t *testing.T, choice string, prob float64, status int, calls *int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(calls, 1)
		var req map[string]json.RawMessage
		_ = json.NewDecoder(r.Body).Decode(&req)
		if _, ok := req["questions"]; !ok {
			t.Error("no questions in the request")
		}
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"answers": map[string]any{
			"route_category": map[string]any{"type": "choice", "choice": choice, "probabilities": map[string]float64{choice: prob}},
		}})
	}))
}

func systemOneConfig(endpoint string) *config.Config {
	cfg := &config.Config{}
	off := false
	cfg.Routing = config.RoutingConfig{
		Enabled: true, Classifier: config.RoutingClassifierSystemOne, MinConfidence: 0.6,
		Categories: map[string]string{"code": "paid", "chat": "local"},
		SystemOne:  &config.RoutingSystemOneConfig{UseDecisionModel: &off, BaseURL: endpoint, Model: "s1", TimeoutMs: 300},
		Models: []config.RoutingModelBackend{
			{Name: "local", Provider: "ollama", Model: "llama3.1", BaseURL: "http://127.0.0.1:11434"},
			{Name: "paid", Provider: "openai", Model: "gpt-4.1-mini"},
		},
	}
	return cfg
}

func TestSystemOneClassifierRoutesByCategory(t *testing.T) {
	var calls int32
	srv := systemOneServer(t, "code", 0.9, http.StatusOK, &calls)
	defer srv.Close()
	r := newEngineRouter(systemOneConfig(srv.URL+"/v1/systemone"), nil, "")
	out := r.RouteDetailed(context.Background(), &ModelRouterInput{Model: "m", Messages: []ChatMessage{{Role: "user", Content: "fix the bug"}}})
	if out.Result != SemanticRouteApplied || out.SelectedModel != "gpt-4.1-mini" || out.Route.Category != "code" || out.Route.Source != "systemone" {
		t.Fatalf("outcome=%+v route=%+v", out, out.Route)
	}
}

func TestSystemOneClassifierContractAndBreaker(t *testing.T) {
	var calls int32
	bad := systemOneServer(t, "poetry", 0.9, http.StatusOK, &calls)
	defer bad.Close()
	c := newSystemOneClassifier(systemOneConfig(bad.URL), "")
	if _, err := c.Classify(context.Background(), engine.ClassifyInput{Text: "x", Categories: []string{"chat", "code"}}); classifierCode(err) != engine.FailureDecode {
		t.Fatalf("out-of-contract category = %v", err)
	}
	if _, err := c.Classify(context.Background(), engine.ClassifyInput{Text: "x"}); classifierCode(err) != engine.FailureConfig {
		t.Fatalf("no categories = %v", err)
	}
	down := systemOneServer(t, "", 0, http.StatusBadGateway, &calls)
	defer down.Close()
	atomic.StoreInt32(&calls, 0)
	c = newSystemOneClassifier(systemOneConfig(down.URL), "")
	in := engine.ClassifyInput{Text: "x", Categories: []string{"code"}}
	for i := 0; i < 3; i++ {
		if _, err := c.Classify(context.Background(), in); classifierCode(err) != engine.FailureUpstreamStatus {
			t.Fatalf("call %d = %v", i, err)
		}
	}
	if _, err := c.Classify(context.Background(), in); classifierCode(err) != engine.FailureBreakerOpen {
		t.Fatalf("after 3 failures = %v, want breaker_open", err)
	}
	if atomic.LoadInt32(&calls) != 3 {
		t.Fatalf("calls = %d, the open breaker must not call", calls)
	}
}

func TestSystemOneLowConfidenceFallsBack(t *testing.T) {
	var calls int32
	srv := systemOneServer(t, "code", 0.3, http.StatusOK, &calls)
	defer srv.Close()
	r := newEngineRouter(systemOneConfig(srv.URL), nil, "")
	out := r.RouteDetailed(context.Background(), &ModelRouterInput{Model: "m", Messages: []ChatMessage{{Role: "user", Content: "fix"}}})
	if out.Result != SemanticRouteFallback || out.FailureCode != SemanticRouteFailureLowConfidence {
		t.Fatalf("outcome=%+v", out)
	}
}
