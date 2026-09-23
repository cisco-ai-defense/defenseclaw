// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package training

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEvaluate_PassesThreshold tests evaluation when local model exceeds threshold.
func TestEvaluate_PassesThreshold(t *testing.T) {
	// Create test eval file
	tempDir := t.TempDir()
	evalFile := filepath.Join(tempDir, "test_eval.jsonl")

	entries := []JSONLEntry{
		{Prompt: "What is 2+2?", Response: "The answer is 4.", ModelUsed: "frontier"},
		{Prompt: "What is the capital of France?", Response: "Paris is the capital.", ModelUsed: "frontier"},
	}

	f, err := os.Create(evalFile)
	if err != nil {
		t.Fatalf("create eval file: %v", err)
	}
	encoder := json.NewEncoder(f)
	for _, entry := range entries {
		if err := encoder.Encode(entry); err != nil {
			t.Fatalf("encode entry: %v", err)
		}
	}
	f.Close()

	// Mock local model server
	localServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		response := openAIChatResponse{
			Choices: []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			}{
				{Message: struct {
					Content string `json:"content"`
				}{Content: "This is a good answer from the local model."}},
			},
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer localServer.Close()

	// Mock judge server (returns scores close to each other, ratio ~0.95)
	judgeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		response := openAIChatResponse{
			Choices: []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			}{
				{Message: struct {
					Content string `json:"content"`
				}{Content: `{"score_a": 9.0, "score_b": 9.5}`}},
			},
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer judgeServer.Close()

	// Run evaluation
	cfg := EvalConfig{
		EvalFilePath:  evalFile,
		LocalEndpoint: localServer.URL,
		LocalModel:    "test-local",
		JudgeEndpoint: judgeServer.URL,
		JudgeModel:    "test-judge",
		JudgeAPIKey:   "",
		EvalPrompts:   0,
		Threshold:     0.90,
	}

	ctx := context.Background()
	result, err := Evaluate(ctx, cfg)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	// Verify results
	if result.PromptsEval != 2 {
		t.Errorf("expected 2 prompts evaluated, got %d", result.PromptsEval)
	}
	if result.Errors != 0 {
		t.Errorf("expected 0 errors, got %d", result.Errors)
	}
	if result.ScoreLocal != 9.0 {
		t.Errorf("expected ScoreLocal=9.0, got %.2f", result.ScoreLocal)
	}
	if result.ScoreFrontier != 9.5 {
		t.Errorf("expected ScoreFrontier=9.5, got %.2f", result.ScoreFrontier)
	}

	expectedRatio := 9.0 / 9.5
	if result.Ratio < expectedRatio-0.01 || result.Ratio > expectedRatio+0.01 {
		t.Errorf("expected Ratio~%.4f, got %.4f", expectedRatio, result.Ratio)
	}
	if !result.Passed {
		t.Errorf("expected evaluation to pass (ratio %.4f >= threshold %.2f)", result.Ratio, cfg.Threshold)
	}
}

// TestEvaluate_FailsThreshold tests evaluation when local model fails to meet threshold.
func TestEvaluate_FailsThreshold(t *testing.T) {
	// Create test eval file
	tempDir := t.TempDir()
	evalFile := filepath.Join(tempDir, "test_eval.jsonl")

	entries := []JSONLEntry{
		{Prompt: "Test prompt", Response: "Frontier response", ModelUsed: "frontier"},
	}

	f, err := os.Create(evalFile)
	if err != nil {
		t.Fatalf("create eval file: %v", err)
	}
	encoder := json.NewEncoder(f)
	for _, entry := range entries {
		if err := encoder.Encode(entry); err != nil {
			t.Fatalf("encode entry: %v", err)
		}
	}
	f.Close()

	// Mock local model server
	localServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := openAIChatResponse{
			Choices: []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			}{
				{Message: struct {
					Content string `json:"content"`
				}{Content: "Poor answer"}},
			},
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer localServer.Close()

	// Mock judge server (local score much lower than frontier)
	judgeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := openAIChatResponse{
			Choices: []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			}{
				{Message: struct {
					Content string `json:"content"`
				}{Content: `{"score_a": 5.0, "score_b": 9.0}`}},
			},
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer judgeServer.Close()

	// Run evaluation
	cfg := EvalConfig{
		EvalFilePath:  evalFile,
		LocalEndpoint: localServer.URL,
		LocalModel:    "test-local",
		JudgeEndpoint: judgeServer.URL,
		JudgeModel:    "test-judge",
		JudgeAPIKey:   "",
		EvalPrompts:   0,
		Threshold:     0.90,
	}

	ctx := context.Background()
	result, err := Evaluate(ctx, cfg)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	// Verify results
	if result.Passed {
		t.Errorf("expected evaluation to fail (ratio %.4f < threshold %.2f)", result.Ratio, cfg.Threshold)
	}
	if result.ScoreLocal != 5.0 {
		t.Errorf("expected ScoreLocal=5.0, got %.2f", result.ScoreLocal)
	}
	if result.ScoreFrontier != 9.0 {
		t.Errorf("expected ScoreFrontier=9.0, got %.2f", result.ScoreFrontier)
	}

	expectedRatio := 5.0 / 9.0
	if result.Ratio < expectedRatio-0.01 || result.Ratio > expectedRatio+0.01 {
		t.Errorf("expected Ratio~%.4f, got %.4f", expectedRatio, result.Ratio)
	}
}

// TestEvaluate_LimitPrompts tests that EvalPrompts parameter correctly limits evaluation.
func TestEvaluate_LimitPrompts(t *testing.T) {
	// Create test eval file with 5 entries
	tempDir := t.TempDir()
	evalFile := filepath.Join(tempDir, "test_eval.jsonl")

	entries := make([]JSONLEntry, 5)
	for i := 0; i < 5; i++ {
		entries[i] = JSONLEntry{
			Prompt:    fmt.Sprintf("Prompt %d", i+1),
			Response:  fmt.Sprintf("Response %d", i+1),
			ModelUsed: "frontier",
		}
	}

	f, err := os.Create(evalFile)
	if err != nil {
		t.Fatalf("create eval file: %v", err)
	}
	encoder := json.NewEncoder(f)
	for _, entry := range entries {
		if err := encoder.Encode(entry); err != nil {
			t.Fatalf("encode entry: %v", err)
		}
	}
	f.Close()

	// Track number of requests
	var localRequests, judgeRequests int

	// Mock local model server
	localServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		localRequests++
		response := openAIChatResponse{
			Choices: []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			}{
				{Message: struct {
					Content string `json:"content"`
				}{Content: "Response"}},
			},
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer localServer.Close()

	// Mock judge server
	judgeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		judgeRequests++
		response := openAIChatResponse{
			Choices: []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			}{
				{Message: struct {
					Content string `json:"content"`
				}{Content: `{"score_a": 8.0, "score_b": 8.0}`}},
			},
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer judgeServer.Close()

	// Run evaluation with limit of 3 prompts
	cfg := EvalConfig{
		EvalFilePath:  evalFile,
		LocalEndpoint: localServer.URL,
		LocalModel:    "test-local",
		JudgeEndpoint: judgeServer.URL,
		JudgeModel:    "test-judge",
		JudgeAPIKey:   "",
		EvalPrompts:   3,
		Threshold:     0.90,
	}

	ctx := context.Background()
	result, err := Evaluate(ctx, cfg)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	// Verify only 3 prompts were evaluated
	if result.PromptsEval != 3 {
		t.Errorf("expected 3 prompts evaluated, got %d", result.PromptsEval)
	}
	if localRequests != 3 {
		t.Errorf("expected 3 local requests, got %d", localRequests)
	}
	if judgeRequests != 3 {
		t.Errorf("expected 3 judge requests, got %d", judgeRequests)
	}
}

// TestParseJudgeScores_ValidJSON tests parsing valid JSON responses.
func TestParseJudgeScores_ValidJSON(t *testing.T) {
	tests := []struct {
		name     string
		response string
		wantA    float64
		wantB    float64
	}{
		{
			name:     "simple json",
			response: `{"score_a": 8.5, "score_b": 9.0}`,
			wantA:    8.5,
			wantB:    9.0,
		},
		{
			name:     "json with surrounding text",
			response: `Here are the scores: {"score_a": 7.0, "score_b": 8.5} Based on my analysis.`,
			wantA:    7.0,
			wantB:    8.5,
		},
		{
			name:     "json with integer scores",
			response: `{"score_a": 10, "score_b": 9}`,
			wantA:    10.0,
			wantB:    9.0,
		},
		{
			name:     "json with whitespace",
			response: `  {  "score_a"  :  5.5  ,  "score_b"  :  6.0  }  `,
			wantA:    5.5,
			wantB:    6.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotA, gotB, err := parseJudgeScores(tt.response)
			if err != nil {
				t.Fatalf("parseJudgeScores failed: %v", err)
			}
			if gotA != tt.wantA {
				t.Errorf("score_a: want %.2f, got %.2f", tt.wantA, gotA)
			}
			if gotB != tt.wantB {
				t.Errorf("score_b: want %.2f, got %.2f", tt.wantB, gotB)
			}
		})
	}
}

// TestParseJudgeScores_InvalidJSON tests graceful handling of invalid responses.
func TestParseJudgeScores_InvalidJSON(t *testing.T) {
	tests := []struct {
		name     string
		response string
		wantErr  string
	}{
		{
			name:     "no json",
			response: "This is just text without any JSON",
			wantErr:  "no JSON object found",
		},
		{
			name:     "malformed json",
			response: `{"score_a": 8.0, "score_b": }`,
			wantErr:  "unmarshal judge scores",
		},
		{
			name:     "missing score_a",
			response: `{"score_b": 9.0}`,
			wantErr:  "", // Will succeed but score_a will be 0
		},
		{
			name:     "score out of range high",
			response: `{"score_a": 15.0, "score_b": 9.0}`,
			wantErr:  "out of range",
		},
		{
			name:     "score out of range low",
			response: `{"score_a": 8.0, "score_b": -2.0}`,
			wantErr:  "out of range",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := parseJudgeScores(tt.response)
			if tt.wantErr == "" && err != nil {
				t.Errorf("expected no error for missing score, got: %v", err)
			}
			if tt.wantErr != "" {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.wantErr)
				} else if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
				}
			}
		})
	}
}

// TestCallChatCompletion_Success tests successful chat completion calls.
func TestCallChatCompletion_Success(t *testing.T) {
	// Mock server
	expectedResponse := "This is the model's response"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type: application/json, got %s", r.Header.Get("Content-Type"))
		}

		// Verify path
		if !strings.HasSuffix(r.URL.Path, "/v1/chat/completions") {
			t.Errorf("expected path ending in /v1/chat/completions, got %s", r.URL.Path)
		}

		// Verify request body
		var req openAIChatRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if req.Model != "test-model" {
			t.Errorf("expected model 'test-model', got %s", req.Model)
		}
		if len(req.Messages) != 1 {
			t.Errorf("expected 1 message, got %d", len(req.Messages))
		}

		// Send response
		response := openAIChatResponse{
			Choices: []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			}{
				{Message: struct {
					Content string `json:"content"`
				}{Content: expectedResponse}},
			},
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Call function
	ctx := context.Background()
	messages := []map[string]interface{}{
		{"role": "user", "content": "Test prompt"},
	}

	response, err := callChatCompletion(ctx, server.URL, "test-model", "", messages)
	if err != nil {
		t.Fatalf("callChatCompletion failed: %v", err)
	}

	if response != expectedResponse {
		t.Errorf("expected response %q, got %q", expectedResponse, response)
	}
}

// TestCallChatCompletion_WithAPIKey tests that API key is properly sent.
func TestCallChatCompletion_WithAPIKey(t *testing.T) {
	expectedAPIKey := "test-api-key-12345"
	receivedAPIKey := ""

	// Mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Capture Authorization header
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			receivedAPIKey = strings.TrimPrefix(authHeader, "Bearer ")
		}

		response := openAIChatResponse{
			Choices: []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			}{
				{Message: struct {
					Content string `json:"content"`
				}{Content: "Response"}},
			},
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Call function with API key
	ctx := context.Background()
	messages := []map[string]interface{}{
		{"role": "user", "content": "Test"},
	}

	_, err := callChatCompletion(ctx, server.URL, "test-model", expectedAPIKey, messages)
	if err != nil {
		t.Fatalf("callChatCompletion failed: %v", err)
	}

	if receivedAPIKey != expectedAPIKey {
		t.Errorf("expected API key %q, got %q", expectedAPIKey, receivedAPIKey)
	}
}

// TestCallChatCompletion_ErrorHandling tests error handling scenarios.
func TestCallChatCompletion_ErrorHandling(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		response   string
		wantErr    string
	}{
		{
			name:       "server error",
			statusCode: http.StatusInternalServerError,
			response:   "Internal server error",
			wantErr:    "unexpected status code 500",
		},
		{
			name:       "unauthorized",
			statusCode: http.StatusUnauthorized,
			response:   "Unauthorized",
			wantErr:    "unexpected status code 401",
		},
		{
			name:       "bad request",
			statusCode: http.StatusBadRequest,
			response:   "Bad request",
			wantErr:    "unexpected status code 400",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.response))
			}))
			defer server.Close()

			ctx := context.Background()
			messages := []map[string]interface{}{
				{"role": "user", "content": "Test"},
			}

			_, err := callChatCompletion(ctx, server.URL, "test-model", "", messages)
			if err == nil {
				t.Errorf("expected error, got nil")
			} else if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
			}
		})
	}
}

// TestEvaluate_ValidationErrors tests configuration validation.
func TestEvaluate_ValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		cfg     EvalConfig
		wantErr string
	}{
		{
			name:    "missing eval file",
			cfg:     EvalConfig{LocalEndpoint: "http://test", LocalModel: "model", JudgeEndpoint: "http://judge", JudgeModel: "judge"},
			wantErr: "eval file path is required",
		},
		{
			name:    "missing local endpoint",
			cfg:     EvalConfig{EvalFilePath: "/tmp/eval.jsonl", LocalModel: "model", JudgeEndpoint: "http://judge", JudgeModel: "judge"},
			wantErr: "local endpoint is required",
		},
		{
			name:    "missing local model",
			cfg:     EvalConfig{EvalFilePath: "/tmp/eval.jsonl", LocalEndpoint: "http://test", JudgeEndpoint: "http://judge", JudgeModel: "judge"},
			wantErr: "local model is required",
		},
		{
			name:    "missing judge endpoint",
			cfg:     EvalConfig{EvalFilePath: "/tmp/eval.jsonl", LocalEndpoint: "http://test", LocalModel: "model", JudgeModel: "judge"},
			wantErr: "judge endpoint is required",
		},
		{
			name:    "missing judge model",
			cfg:     EvalConfig{EvalFilePath: "/tmp/eval.jsonl", LocalEndpoint: "http://test", LocalModel: "model", JudgeEndpoint: "http://judge"},
			wantErr: "judge model is required",
		},
		{
			name:    "invalid threshold low",
			cfg:     EvalConfig{EvalFilePath: "/tmp/eval.jsonl", LocalEndpoint: "http://test", LocalModel: "model", JudgeEndpoint: "http://judge", JudgeModel: "judge", Threshold: -0.1},
			wantErr: "threshold must be between 0 and 1",
		},
		{
			name:    "invalid threshold high",
			cfg:     EvalConfig{EvalFilePath: "/tmp/eval.jsonl", LocalEndpoint: "http://test", LocalModel: "model", JudgeEndpoint: "http://judge", JudgeModel: "judge", Threshold: 1.5},
			wantErr: "threshold must be between 0 and 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			_, err := Evaluate(ctx, tt.cfg)
			if err == nil {
				t.Errorf("expected error, got nil")
			} else if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
			}
		})
	}
}
