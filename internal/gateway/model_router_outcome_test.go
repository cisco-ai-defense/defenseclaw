// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRemoteRouterRouteDetailedFailureCodes(t *testing.T) {
	t.Parallel()

	t.Run("timeout", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			time.Sleep(200 * time.Millisecond)
		}))
		t.Cleanup(server.Close)
		client := NewRemoteRouterClient(server.URL, 20)
		outcome := client.RouteDetailed(context.Background(), &ModelRouterInput{Model: "requested"})
		if outcome.Result != SemanticRouteFallback || outcome.FailureCode != SemanticRouteFailureTimeout {
			t.Fatalf("timeout outcome=%+v", outcome)
		}
		if outcome.Decision != nil {
			t.Fatal("timeout must not apply a route")
		}
	})

	t.Run("upstream_status", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`{"error":"secret-key-must-not-be-copied"}`))
		}))
		t.Cleanup(server.Close)
		client := NewRemoteRouterClient(server.URL, 500)
		outcome := client.RouteDetailed(context.Background(), &ModelRouterInput{Model: "requested"})
		if outcome.Result != SemanticRouteFallback || outcome.FailureCode != SemanticRouteFailureUpstreamStatus {
			t.Fatalf("upstream outcome=%+v", outcome)
		}
	})

	t.Run("decode_failure", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("not-json"))
		}))
		t.Cleanup(server.Close)
		client := NewRemoteRouterClient(server.URL, 500)
		outcome := client.RouteDetailed(context.Background(), &ModelRouterInput{Model: "requested"})
		if outcome.Result != SemanticRouteFallback || outcome.FailureCode != SemanticRouteFailureDecode {
			t.Fatalf("decode outcome=%+v", outcome)
		}
	})

	t.Run("unknown_alias", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(classifyResponse{RecommendedModel: "missing-alias"})
		}))
		t.Cleanup(server.Close)
		client := NewConfiguredRemoteRouterClient(server.URL, 500, []ModelRouterBackend{{
			Name: "known", Provider: "ollama", Model: "llama3", BaseURL: "http://127.0.0.1:11434",
		}}, "")
		outcome := client.RouteDetailed(context.Background(), &ModelRouterInput{Model: "requested"})
		if outcome.Result != SemanticRouteFallback || outcome.FailureCode != SemanticRouteFailureUnknownAlias {
			t.Fatalf("unknown alias outcome=%+v", outcome)
		}
	})

	t.Run("applied override", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasSuffix(r.URL.Path, "/classify/intent") {
				t.Fatalf("path=%s", r.URL.Path)
			}
			_ = json.NewEncoder(w).Encode(classifyResponse{
				RecommendedModel: "fast",
				RoutingDecision:  "continue",
			})
		}))
		t.Cleanup(server.Close)
		client := NewConfiguredRemoteRouterClient(server.URL, 500, []ModelRouterBackend{{
			Name: "fast", Provider: "ollama", Model: "llama3.1", BaseURL: "http://127.0.0.1:11434",
		}}, "")
		outcome := client.RouteDetailed(context.Background(), &ModelRouterInput{
			Model: "requested", RequestModel: "requested",
		})
		if outcome.Result != SemanticRouteApplied || outcome.FailureCode != SemanticRouteFailureNone {
			t.Fatalf("applied outcome=%+v", outcome)
		}
		if !outcome.OverrideApplied || outcome.SelectedProvider != "ollama" || outcome.SelectedModel != "llama3.1" {
			t.Fatalf("override fields=%+v", outcome)
		}
		if outcome.Decision == nil || outcome.Decision.Reason == "" {
			t.Fatal("decision reason stays on the header-only struct")
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
