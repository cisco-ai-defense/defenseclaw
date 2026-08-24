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
			t.Errorf("decode request: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
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
	// Create and immediately close a server to get an unreachable URL.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	unreachableURL := srv.URL
	srv.Close()

	client := NewRemoteRouterClient(unreachableURL, 10)
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
	// Create and immediately close a server to get an unreachable URL.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	unreachableURL := srv.URL
	srv.Close()

	client := NewRemoteRouterClient(unreachableURL, 10)
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

func TestRemoteRouterClient_Route_NilInput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not be called with nil input")
	}))
	defer srv.Close()

	client := NewRemoteRouterClient(srv.URL, 100)
	decision := client.Route(context.Background(), nil)

	if decision != nil {
		t.Errorf("expected nil decision for nil input, got %+v", decision)
	}
}

func TestRemoteRouterClient_Route_PluginOutputs_SystemPrompt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"recommended_model": "claude-sonnet",
			"routing_decision":  "code_route",
			"classification":    map[string]interface{}{"category": "cs", "confidence": 0.9},
			"decision_result":   map[string]interface{}{"decision_name": "code_route", "confidence": 0.9},
			"plugin_outputs": map[string]interface{}{
				"system_prompt":    "You are a code expert.",
				"reasoning_effort": "high",
				"use_reasoning":    true,
				"lora_name":        "code-adapter",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := NewRemoteRouterClient(srv.URL, 100)
	input := &ModelRouterInput{
		Model:    "auto",
		Messages: []ChatMessage{{Role: "user", Content: "implement fibonacci"}},
	}

	decision := client.Route(context.Background(), input)

	if decision == nil {
		t.Fatal("expected decision, got nil")
	}
	if decision.Model != "claude-sonnet" {
		t.Errorf("expected model 'claude-sonnet', got %q", decision.Model)
	}
	if decision.SystemPrompt != "You are a code expert." {
		t.Errorf("expected system prompt, got %q", decision.SystemPrompt)
	}
	if decision.ReasoningEffort != "high" {
		t.Errorf("expected reasoning_effort 'high', got %q", decision.ReasoningEffort)
	}
	if decision.UseReasoning != true {
		t.Error("expected use_reasoning true")
	}
	if decision.LoRAName != "code-adapter" {
		t.Errorf("expected lora_name 'code-adapter', got %q", decision.LoRAName)
	}
}

func TestRemoteRouterClient_Route_PluginOutputs_CachedResponse(t *testing.T) {
	cachedBody := `{"choices":[{"message":{"content":"cached answer"}}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"recommended_model": "cached",
			"routing_decision":  "cache_hit",
			"classification":    map[string]interface{}{"category": "general", "confidence": 1.0},
			"decision_result":   map[string]interface{}{"decision_name": "cache_hit", "confidence": 1.0},
			"plugin_outputs": map[string]interface{}{
				"cached_response": map[string]interface{}{
					"body":   json.RawMessage(cachedBody),
					"status": 200,
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := NewRemoteRouterClient(srv.URL, 100)
	input := &ModelRouterInput{
		Model:    "auto",
		Messages: []ChatMessage{{Role: "user", Content: "what is 2+2"}},
	}

	decision := client.Route(context.Background(), input)

	if decision == nil {
		t.Fatal("expected decision, got nil")
	}
	if !decision.CacheHit {
		t.Error("expected CacheHit true")
	}
	if decision.CachedResponse == nil {
		t.Fatal("expected CachedResponse non-nil")
	}
}

func TestRemoteRouterClient_Route_PluginOutputs_HeaderMutations(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"recommended_model": "gpt-4o",
			"routing_decision":  "route",
			"classification":    map[string]interface{}{"category": "general", "confidence": 0.8},
			"decision_result":   map[string]interface{}{"decision_name": "route", "confidence": 0.8},
			"plugin_outputs": map[string]interface{}{
				"header_mutations": map[string]interface{}{
					"add":    []interface{}{map[string]interface{}{"name": "X-Route", "value": "premium"}},
					"delete": []interface{}{"X-Debug"},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := NewRemoteRouterClient(srv.URL, 100)
	input := &ModelRouterInput{
		Model:    "auto",
		Messages: []ChatMessage{{Role: "user", Content: "hello"}},
	}

	decision := client.Route(context.Background(), input)

	if decision == nil {
		t.Fatal("expected decision, got nil")
	}
	if decision.HeaderMutations == nil {
		t.Fatal("expected HeaderMutations non-nil")
	}
	if len(decision.HeaderMutations.Add) != 1 {
		t.Fatalf("expected 1 add mutation, got %d", len(decision.HeaderMutations.Add))
	}
	if decision.HeaderMutations.Add[0].Name != "X-Route" {
		t.Errorf("expected header name 'X-Route', got %q", decision.HeaderMutations.Add[0].Name)
	}
	if len(decision.HeaderMutations.Delete) != 1 {
		t.Fatalf("expected 1 delete mutation, got %d", len(decision.HeaderMutations.Delete))
	}
}

func TestRemoteRouterClient_Route_PluginOutputs_RAGContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"recommended_model": "gpt-4o",
			"routing_decision":  "rag_route",
			"classification":    map[string]interface{}{"category": "tech", "confidence": 0.85},
			"decision_result":   map[string]interface{}{"decision_name": "rag_route", "confidence": 0.85},
			"plugin_outputs": map[string]interface{}{
				"rag_context": []interface{}{
					map[string]interface{}{"content": "Document content here", "source": "docs/readme.md", "similarity": 0.92},
					map[string]interface{}{"content": "Another doc", "source": "docs/api.md", "similarity": 0.78},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := NewRemoteRouterClient(srv.URL, 100)
	input := &ModelRouterInput{
		Model:    "auto",
		Messages: []ChatMessage{{Role: "user", Content: "how does the API work?"}},
	}

	decision := client.Route(context.Background(), input)

	if decision == nil {
		t.Fatal("expected decision, got nil")
	}
	if len(decision.RAGDocuments) != 2 {
		t.Fatalf("expected 2 RAG documents, got %d", len(decision.RAGDocuments))
	}
	if decision.RAGDocuments[0].Content != "Document content here" {
		t.Errorf("unexpected RAG content: %q", decision.RAGDocuments[0].Content)
	}
	if decision.RAGDocuments[0].Source != "docs/readme.md" {
		t.Errorf("unexpected RAG source: %q", decision.RAGDocuments[0].Source)
	}
	if decision.RAGDocuments[0].Similarity != 0.92 {
		t.Errorf("unexpected RAG similarity: %f", decision.RAGDocuments[0].Similarity)
	}
}

func TestRemoteRouterClient_Route_PluginOutputs_CompressedPrompt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"recommended_model": "gpt-4o",
			"routing_decision":  "compress_route",
			"classification":    map[string]interface{}{"category": "general", "confidence": 0.7},
			"decision_result":   map[string]interface{}{"decision_name": "compress_route", "confidence": 0.7},
			"plugin_outputs": map[string]interface{}{
				"compressed_prompt": map[string]interface{}{
					"messages": []interface{}{
						map[string]interface{}{"role": "user", "content": "compressed version of the prompt"},
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := NewRemoteRouterClient(srv.URL, 100)
	input := &ModelRouterInput{
		Model:    "auto",
		Messages: []ChatMessage{{Role: "user", Content: "very long original prompt that gets compressed..."}},
	}

	decision := client.Route(context.Background(), input)

	if decision == nil {
		t.Fatal("expected decision, got nil")
	}
	if len(decision.CompressedMessages) != 1 {
		t.Fatalf("expected 1 compressed message, got %d", len(decision.CompressedMessages))
	}
	if decision.CompressedMessages[0].Role != "user" {
		t.Errorf("expected role 'user', got %q", decision.CompressedMessages[0].Role)
	}
	if decision.CompressedMessages[0].Content != "compressed version of the prompt" {
		t.Errorf("unexpected compressed content: %q", decision.CompressedMessages[0].Content)
	}
}

func TestRemoteRouterClient_Route_PluginOutputs_Warnings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"recommended_model": "gpt-4o",
			"routing_decision":  "route",
			"classification":    map[string]interface{}{"category": "general", "confidence": 0.6},
			"decision_result":   map[string]interface{}{"decision_name": "route", "confidence": 0.6},
			"warnings":          []interface{}{"low confidence routing", "embedding model unavailable"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := NewRemoteRouterClient(srv.URL, 100)
	input := &ModelRouterInput{
		Model:    "auto",
		Messages: []ChatMessage{{Role: "user", Content: "test"}},
	}

	decision := client.Route(context.Background(), input)

	if decision == nil {
		t.Fatal("expected decision, got nil")
	}
	if len(decision.Warnings) != 2 {
		t.Fatalf("expected 2 warnings, got %d", len(decision.Warnings))
	}
}

func TestRemoteRouterClient_Route_RichContext(t *testing.T) {
	var receivedReq classifyRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&receivedReq)
		resp := classifyResponse{
			RecommendedModel: "model",
			RoutingDecision:  "route",
			Classification:   classifyClassification{Category: "general", Confidence: 0.8},
			DecisionResult:   classifyDecisionResult{DecisionName: "route", Confidence: 0.8},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := NewRemoteRouterClient(srv.URL, 100)
	input := &ModelRouterInput{
		Model:        "auto",
		RequestModel: "specific-model",
		Messages:     []ChatMessage{{Role: "user", Content: "hello"}},
		Stream:       true,
		SessionID:    "sess-123",
		UserID:       "user-456",
		UserGroups:   []string{"premium", "engineering"},
		Headers:      map[string]string{"x-tenant": "acme"},
		Metadata:     map[string]interface{}{"dc_severity": "LOW"},
	}

	client.Route(context.Background(), input)

	if receivedReq.Model != "specific-model" {
		t.Errorf("expected model 'specific-model', got %q", receivedReq.Model)
	}
	if receivedReq.Stream != true {
		t.Error("expected stream true")
	}
	if receivedReq.SessionID != "sess-123" {
		t.Errorf("expected session_id 'sess-123', got %q", receivedReq.SessionID)
	}
	if receivedReq.UserID != "user-456" {
		t.Errorf("expected user_id 'user-456', got %q", receivedReq.UserID)
	}
	if len(receivedReq.UserGroups) != 2 {
		t.Errorf("expected 2 user_groups, got %d", len(receivedReq.UserGroups))
	}
	if receivedReq.Headers["x-tenant"] != "acme" {
		t.Errorf("expected header x-tenant=acme, got %v", receivedReq.Headers)
	}
}
