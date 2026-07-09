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
	// Mock SR server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/route" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", r.Method)
		}

		var req routeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}

		if len(req.Messages) != 2 {
			t.Errorf("expected 2 messages, got %d", len(req.Messages))
		}
		if req.Model != "gpt-4" {
			t.Errorf("expected model gpt-4, got %s", req.Model)
		}

		resp := routeResponse{
			Backend:    "openai-primary",
			Model:      "gpt-4o-mini",
			Provider:   "openai",
			BaseURL:    "https://api.openai.com/v1",
			APIKey:     "sk-test-key",
			Algorithm:  "semantic",
			Decision:   "route",
			Confidence: 0.95,
			Reason:     "high confidence match",
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
	if decision.TargetURL != "https://api.openai.com/v1" {
		t.Errorf("expected TargetURL https://api.openai.com/v1, got %s", decision.TargetURL)
	}
	if decision.Model != "gpt-4o-mini" {
		t.Errorf("expected Model gpt-4o-mini, got %s", decision.Model)
	}
	if decision.APIKey != "sk-test-key" {
		t.Errorf("expected APIKey sk-test-key, got %s", decision.APIKey)
	}
	if decision.Reason != "high confidence match" {
		t.Errorf("expected Reason 'high confidence match', got %s", decision.Reason)
	}
}

func TestRemoteRouterClient_Route_SRDown(t *testing.T) {
	// No server running - should gracefully return nil
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
	// Mock SR that delays longer than client timeout
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(routeResponse{
			Backend: "test",
			Model:   "test-model",
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
	// Mock SR returns invalid JSON
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
	// Mock SR returns 500
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

func TestRemoteRouterClient_Route_EmptyReason(t *testing.T) {
	// Mock SR returns response without reason field
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := routeResponse{
			Backend:   "openai-primary",
			Model:     "gpt-4o",
			Provider:  "openai",
			BaseURL:   "https://api.openai.com/v1",
			Algorithm: "semantic",
			Decision:  "route",
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

	if decision == nil {
		t.Fatal("expected decision, got nil")
	}
	if decision.Reason == "" {
		t.Error("expected generated reason when SR returns empty reason")
	}
	// Should contain decision, backend, algorithm
	if decision.Reason != "decision=route backend=openai-primary algorithm=semantic" {
		t.Errorf("unexpected generated reason: %s", decision.Reason)
	}
}

func TestRemoteRouterClient_Healthy_Up(t *testing.T) {
	// Mock healthy SR
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
	// No server running
	client := NewRemoteRouterClient("http://127.0.0.1:9998", 10)
	healthy := client.Healthy(context.Background())

	if healthy {
		t.Error("expected healthy=false when SR is unreachable")
	}
}

func TestRemoteRouterClient_Healthy_Unhealthy(t *testing.T) {
	// Server returns non-200
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
	var client *RemoteRouterClient = nil
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
	// Test that invalid timeout defaults to 50ms
	client := NewRemoteRouterClient("http://example.com", 0)
	if client.timeout != 50*time.Millisecond {
		t.Errorf("expected default timeout 50ms, got %v", client.timeout)
	}

	client = NewRemoteRouterClient("http://example.com", -10)
	if client.timeout != 50*time.Millisecond {
		t.Errorf("expected default timeout 50ms for negative value, got %v", client.timeout)
	}
}
