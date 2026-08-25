// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
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

func TestRemoteRouterClient_Route_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/classify/intent" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", r.Method)
		}

		var req classifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}

		if len(req.Messages) != 2 {
			t.Errorf("expected 2 messages, got %d", len(req.Messages))
		}

		resp := classifyResponse{
			RecommendedModel: "gpt-4o-mini",
			RoutingDecision:  "route",
			Classification: classifyClassification{
				Category:   "general",
				Confidence: 0.95,
			},
			DecisionResult: classifyDecisionResult{
				DecisionName: "high-confidence",
				Confidence:   0.95,
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := NewRemoteRouterClient(srv.URL, 100)
	input := &ModelRouterInput{
		Model: "gpt-4",
		Messages: []ChatMessage{
			{Role: "system", Content: "You are a helpful assistant."},
			{Role: "user", Content: "Hello!"},
		},
		Stream: false,
	}

	decision := client.Route(context.Background(), input)

	if decision == nil {
		t.Fatal("expected decision, got nil")
	}
	if decision.Model != "gpt-4o-mini" {
		t.Errorf("expected Model gpt-4o-mini, got %s", decision.Model)
	}
	if decision.Reason == "" {
		t.Error("expected non-empty Reason")
	}
}

func TestRemoteRouterClient_Route_SRDown(t *testing.T) {
	client := NewRemoteRouterClient("http://127.0.0.1:9999", 10)
	input := &ModelRouterInput{
		Model: "gpt-4",
		Messages: []ChatMessage{
			{Role: "user", Content: "Hello"},
		},
	}

	decision := client.Route(context.Background(), input)

	if decision != nil {
		t.Errorf("expected nil decision when SR is down, got %+v", decision)
	}
}

func TestRemoteRouterClient_Route_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(classifyResponse{
			RecommendedModel: "test-model",
			RoutingDecision:  "route",
		})
	}))
	defer srv.Close()

	client := NewRemoteRouterClient(srv.URL, 10) // 10ms timeout
	input := &ModelRouterInput{
		Model:    "gpt-4",
		Messages: []ChatMessage{{Role: "user", Content: "Hello"}},
	}

	decision := client.Route(context.Background(), input)

	if decision != nil {
		t.Errorf("expected nil decision on timeout, got %+v", decision)
	}
}

func TestRemoteRouterClient_Route_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"invalid json`))
	}))
	defer srv.Close()

	client := NewRemoteRouterClient(srv.URL, 100)
	input := &ModelRouterInput{
		Model:    "gpt-4",
		Messages: []ChatMessage{{Role: "user", Content: "Hello"}},
	}

	decision := client.Route(context.Background(), input)

	if decision != nil {
		t.Errorf("expected nil decision on invalid JSON, got %+v", decision)
	}
}

func TestRemoteRouterClient_Route_ErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "internal error"}`))
	}))
	defer srv.Close()

	client := NewRemoteRouterClient(srv.URL, 100)
	input := &ModelRouterInput{
		Model:    "gpt-4",
		Messages: []ChatMessage{{Role: "user", Content: "Hello"}},
	}

	decision := client.Route(context.Background(), input)

	if decision != nil {
		t.Errorf("expected nil decision on error status, got %+v", decision)
	}
}

func TestRemoteRouterClient_Route_EmptyModel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := classifyResponse{
			RecommendedModel: "",
			RoutingDecision:  "fallback",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := NewRemoteRouterClient(srv.URL, 100)
	input := &ModelRouterInput{
		Model:    "gpt-4",
		Messages: []ChatMessage{{Role: "user", Content: "Hello"}},
	}

	decision := client.Route(context.Background(), input)

	if decision != nil {
		t.Errorf("expected nil decision when recommended_model is empty, got %+v", decision)
	}
}

func TestRemoteRouterClient_Healthy_Up(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer srv.Close()

	client := NewRemoteRouterClient(srv.URL, 100)
	healthy := client.Healthy(context.Background())

	if !healthy {
		t.Error("expected healthy=true when SR returns 200")
	}
}

func TestRemoteRouterClient_Healthy_Down(t *testing.T) {
	client := NewRemoteRouterClient("http://127.0.0.1:9998", 10)
	healthy := client.Healthy(context.Background())

	if healthy {
		t.Error("expected healthy=false when SR is unreachable")
	}
}

func TestRemoteRouterClient_Healthy_Unhealthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	client := NewRemoteRouterClient(srv.URL, 100)
	healthy := client.Healthy(context.Background())

	if healthy {
		t.Error("expected healthy=false when SR returns 503")
	}
}

func TestRemoteRouterClient_NilClient(t *testing.T) {
	var client *RemoteRouterClient
	input := &ModelRouterInput{
		Model:    "gpt-4",
		Messages: []ChatMessage{{Role: "user", Content: "Hello"}},
	}

	decision := client.Route(context.Background(), input)

	if decision != nil {
		t.Errorf("expected nil decision from nil client, got %+v", decision)
	}
}

func TestRemoteRouterClient_EmptyEndpoint(t *testing.T) {
	client := NewRemoteRouterClient("", 100)
	input := &ModelRouterInput{
		Model:    "gpt-4",
		Messages: []ChatMessage{{Role: "user", Content: "Hello"}},
	}

	decision := client.Route(context.Background(), input)

	if decision != nil {
		t.Errorf("expected nil decision from empty endpoint, got %+v", decision)
	}
}

func TestRemoteRouterClient_DefaultTimeout(t *testing.T) {
	client := NewRemoteRouterClient("http://example.com", 0)
	if client.timeout != 100*time.Millisecond {
		t.Errorf("expected default timeout 100ms, got %v", client.timeout)
	}

	client = NewRemoteRouterClient("http://example.com", -10)
	if client.timeout != 100*time.Millisecond {
		t.Errorf("expected default timeout 100ms for negative value, got %v", client.timeout)
	}
}
