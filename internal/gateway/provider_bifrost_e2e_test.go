// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

// ---------------------------------------------------------------------------
// Provider factory: Bifrost creation for every supported provider
// ---------------------------------------------------------------------------

func TestBifrostE2E_AllProvidersCreate(t *testing.T) {
	providers := []struct {
		input       string
		apiKey      string
		wantProv    schemas.ModelProvider
		wantModelID string
	}{
		{"openai/gpt-4o", "sk-test", schemas.OpenAI, "gpt-4o"},
		{"anthropic/claude-sonnet-4-20250514", "sk-ant-test", schemas.Anthropic, "claude-sonnet-4-20250514"},
		{"bedrock/us.anthropic.claude-3-5-haiku-20241022-v1:0", "ABSKtest", schemas.Bedrock, "us.anthropic.claude-3-5-haiku-20241022-v1:0"},
		{"azure/gpt-4.1", "azure-key", schemas.Azure, "gpt-4.1"},
		{"gemini/gemini-2.0-flash", "AIzaTest", schemas.Gemini, "gemini-2.0-flash"},
		{"gemini-openai/gemini-2.0-flash", "AIzaTest", schemas.Gemini, "gemini-2.0-flash"},
		{"openrouter/meta/llama-3", "or-test", schemas.ModelProvider("openrouter"), "meta/llama-3"},
		{"groq/llama-3", "gsk-test", schemas.ModelProvider("groq"), "llama-3"},
		{"mistral/mistral-large", "ms-test", schemas.ModelProvider("mistral"), "mistral-large"},
		{"ollama/llama3", "ollama-test", schemas.ModelProvider("ollama"), "llama3"},
		{"cohere/command-r", "co-test", schemas.ModelProvider("cohere"), "command-r"},
		{"perplexity/sonar-small", "pplx-test", schemas.ModelProvider("perplexity"), "sonar-small"},
		{"cerebras/llama3", "cb-test", schemas.ModelProvider("cerebras"), "llama3"},
		{"fireworks/llama-v3", "fw-test", schemas.ModelProvider("fireworks"), "llama-v3"},
		{"xai/grok-2", "xai-test", schemas.ModelProvider("xai"), "grok-2"},
		{"huggingface/meta-llama/Llama-3", "hf-test", schemas.ModelProvider("huggingface"), "meta-llama/Llama-3"},
		{"replicate/meta/llama-3", "r8-test", schemas.ModelProvider("replicate"), "meta/llama-3"},
	}
	for _, tt := range providers {
		t.Run(tt.input, func(t *testing.T) {
			p, err := NewProvider(tt.input, tt.apiKey)
			if err != nil {
				t.Fatalf("NewProvider(%q): %v", tt.input, err)
			}
			bp, ok := p.(*bifrostProvider)
			if !ok {
				t.Fatalf("expected *bifrostProvider, got %T", p)
			}
			if bp.providerKey != tt.wantProv {
				t.Errorf("providerKey = %q, want %q", bp.providerKey, tt.wantProv)
			}
			if bp.model != tt.wantModelID {
				t.Errorf("model = %q, want %q", bp.model, tt.wantModelID)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Provider inference: API key format → provider detection
// ---------------------------------------------------------------------------

func TestBifrostE2E_InferProviderFromAPIKey(t *testing.T) {
	tests := []struct {
		model    string
		apiKey   string
		wantProv string
	}{
		{"some-model", "ABSKtest123", "bedrock"},
		{"claude-3-sonnet", "test-key", "anthropic"},
		{"claude-haiku-4-5", "sk-ant-api123", "anthropic"},
		{"gemini-2.0-flash", "test-key", "gemini"},
		{"anything", "AIzaSyExample", "gemini"},
		{"gpt-4o", "sk-proj-abc", "openai"},
		{"gpt-4o", "sk-test", "openai"},
		{"unknown-model", "regular-key", "openai"},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_%s", tt.model, tt.wantProv), func(t *testing.T) {
			got := inferProvider(tt.model, tt.apiKey)
			if got != tt.wantProv {
				t.Errorf("inferProvider(%q, %q) = %q, want %q", tt.model, tt.apiKey, got, tt.wantProv)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// splitModel edge cases
// ---------------------------------------------------------------------------

func TestBifrostE2E_SplitModelEdgeCases(t *testing.T) {
	tests := []struct {
		input     string
		wantProv  string
		wantModel string
	}{
		{"openai/gpt-4o", "openai", "gpt-4o"},
		{"anthropic/claude-opus-4-5", "anthropic", "claude-opus-4-5"},
		{"openrouter/anthropic/claude-opus-4-5", "openrouter", "anthropic/claude-opus-4-5"},
		{"bedrock/us.anthropic.claude-3-5-haiku-20241022-v1:0", "bedrock", "us.anthropic.claude-3-5-haiku-20241022-v1:0"},
		{"gemini-openai/gemini-2.0-flash", "gemini-openai", "gemini-2.0-flash"},
		{"vllm/meta-llama/Llama-3", "vllm", "meta-llama/Llama-3"},
		{"unknown/foo", "", "unknown/foo"},
		{"gpt-4o", "", "gpt-4o"},
		{"", "", ""},
		{"claude-sonnet-4-20250514", "", "claude-sonnet-4-20250514"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			prov, model := splitModel(tt.input)
			if prov != tt.wantProv || model != tt.wantModel {
				t.Errorf("splitModel(%q) = (%q, %q), want (%q, %q)",
					tt.input, prov, model, tt.wantProv, tt.wantModel)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// BaseURL propagation through Bifrost
// ---------------------------------------------------------------------------

func TestBifrostE2E_BaseURLPropagation(t *testing.T) {
	tests := []struct {
		name     string
		model    string
		apiKey   string
		baseURL  string
		wantBase string
	}{
		{"custom_anthropic", "anthropic/claude-3-sonnet", "sk-ant-test", "http://proxy:8080/v1", "http://proxy:8080/v1"},
		{"custom_openai", "openai/gpt-4", "sk-test", "http://localhost:11434/v1", "http://localhost:11434/v1"},
		{"empty_base_url", "openai/gpt-4", "sk-test", "", ""},
		{"trailing_slash_stripped", "openai/gpt-4", "sk-test", "http://proxy:8080/v1/", "http://proxy:8080/v1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := NewProviderWithBase(tt.model, tt.apiKey, tt.baseURL)
			if err != nil {
				t.Fatalf("NewProviderWithBase: %v", err)
			}
			bp := p.(*bifrostProvider)
			if bp.baseURL != tt.wantBase {
				t.Errorf("baseURL = %q, want %q", bp.baseURL, tt.wantBase)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Registration state management
// ---------------------------------------------------------------------------

func TestBifrostE2E_RegistrationIdempotency(t *testing.T) {
	provKey := schemas.ModelProvider("e2e-idempotent-test")

	bifrostAccMu.Lock()
	delete(bifrostAccounts, provKey)
	delete(bifrostUpdated, provKey)
	bifrostAccMu.Unlock()

	defer func() {
		bifrostAccMu.Lock()
		delete(bifrostAccounts, provKey)
		delete(bifrostUpdated, provKey)
		bifrostAccMu.Unlock()
	}()

	// First registration must report changed.
	if !registerProvider(provKey, "key-1", "") {
		t.Error("first registration should report changed")
	}

	// Same key+base = no change.
	if registerProvider(provKey, "key-1", "") {
		t.Error("identical registration should not report changed")
	}

	// Different key = changed.
	if !registerProvider(provKey, "key-2", "") {
		t.Error("key change should report changed")
	}

	// Verify key was updated.
	bifrostAccMu.Lock()
	acc := bifrostAccounts[provKey]
	bifrostAccMu.Unlock()
	if acc.keys[0].Value.Val != "key-2" {
		t.Errorf("key should be key-2, got %q", acc.keys[0].Value.Val)
	}

	// Different base URL = changed.
	if !registerProvider(provKey, "key-2", "http://custom:8080") {
		t.Error("base URL change should report changed")
	}

	bifrostAccMu.Lock()
	if bifrostAccounts[provKey].config.NetworkConfig.BaseURL != "http://custom:8080" {
		t.Error("base URL should be updated")
	}
	bifrostAccMu.Unlock()
}

// ---------------------------------------------------------------------------
// Proxy integration: header-based provider resolution → Bifrost
// ---------------------------------------------------------------------------

func TestBifrostE2E_ProxyResolveFromHeaders(t *testing.T) {
	prov := &mockProvider{}
	insp := newMockInspector()
	proxy := newTestProxy(t, prov, insp, "observe")
	proxy.resolveProviderFn = proxy.resolveProviderFromHeaders

	tests := []struct {
		name      string
		targetURL string
		apiKey    string
		model     string
		wantNil   bool
		wantType  string
	}{
		{
			name:      "openai_from_header",
			targetURL: "https://api.openai.com",
			apiKey:    "sk-openai-key",
			model:     "gpt-4",
			wantType:  "*gateway.bifrostProvider",
		},
		{
			name:      "anthropic_from_header",
			targetURL: "https://api.anthropic.com",
			apiKey:    "sk-ant-key",
			model:     "claude-opus-4-5",
			wantType:  "*gateway.bifrostProvider",
		},
		{
			name:      "azure_from_header",
			targetURL: "https://myresource.openai.azure.com",
			apiKey:    "azure-test-key",
			model:     "gpt-4.1",
			wantType:  "*gateway.bifrostProvider",
		},
		{
			name:      "no_target_with_config_fallback",
			targetURL: "",
			apiKey:    "sk-key",
			model:     "gpt-4",
			wantType:  "*gateway.bifrostProvider",
		},
		{
			name:      "no_api_key_returns_nil",
			targetURL: "",
			apiKey:    "",
			model:     "gpt-4",
			wantNil:   true,
		},
		{
			name:      "unknown_domain_returns_nil",
			targetURL: "https://unknown-llm.example.com",
			apiKey:    "sk-key",
			model:     "gpt-4",
			wantNil:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &ChatRequest{Model: tt.model}
			httpReq := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
			if tt.targetURL != "" {
				httpReq.Header.Set("X-DC-Target-URL", tt.targetURL)
			}
			if tt.apiKey != "" {
				httpReq.Header.Set("X-AI-Auth", "Bearer "+tt.apiKey)
			}
			req.TargetURL = tt.targetURL
			req.TargetAPIKey = tt.apiKey

			p := proxy.resolveProviderFromHeaders(req)

			if tt.wantNil {
				if p != nil {
					t.Errorf("expected nil provider, got %T", p)
				}
				return
			}
			if p == nil {
				t.Fatal("expected non-nil provider")
			}
			gotType := fmt.Sprintf("%T", p)
			if gotType != tt.wantType {
				t.Errorf("provider type = %q, want %q", gotType, tt.wantType)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// API key resolution: env → dotenv → header chain
// ---------------------------------------------------------------------------

func TestBifrostE2E_APIKeyResolution(t *testing.T) {
	t.Run("from_env_var", func(t *testing.T) {
		t.Setenv("TEST_BIFROST_E2E_KEY", "test-api-key-from-env")
		got := ResolveAPIKey("TEST_BIFROST_E2E_KEY", "")
		if got != "test-api-key-from-env" {
			t.Errorf("got %q, want test-api-key-from-env", got)
		}
	})

	t.Run("env_var_empty_no_dotenv", func(t *testing.T) {
		got := ResolveAPIKey("NONEXISTENT_E2E_KEY_12345", "")
		if got != "" {
			t.Errorf("expected empty, got %q", got)
		}
	})

	t.Run("from_dotenv_file", func(t *testing.T) {
		dir := t.TempDir()
		dotenvPath := dir + "/.env"
		if err := os.WriteFile(dotenvPath, []byte("TEST_DOTENV_KEY=dotenv-value-123\n"), 0600); err != nil {
			t.Fatal(err)
		}
		got := ResolveAPIKey("TEST_DOTENV_KEY", dotenvPath)
		if got != "dotenv-value-123" {
			t.Errorf("got %q, want dotenv-value-123", got)
		}
	})

	t.Run("env_var_takes_precedence_over_dotenv", func(t *testing.T) {
		t.Setenv("TEST_BIFROST_PRECEDENCE", "from-env")
		dir := t.TempDir()
		dotenvPath := dir + "/.env"
		if err := os.WriteFile(dotenvPath, []byte("TEST_BIFROST_PRECEDENCE=from-dotenv\n"), 0600); err != nil {
			t.Fatal(err)
		}
		got := ResolveAPIKey("TEST_BIFROST_PRECEDENCE", dotenvPath)
		if got != "from-env" {
			t.Errorf("env var should take precedence, got %q", got)
		}
	})
}

// ---------------------------------------------------------------------------
// Bifrost message conversion round-trip
// ---------------------------------------------------------------------------

func TestBifrostE2E_MessageRoundTrip(t *testing.T) {
	original := []ChatMessage{
		{Role: "system", Content: "You are a security analyst."},
		{Role: "user", Content: "Check this for PII: john@example.com"},
		{Role: "assistant", Content: "I found an email address."},
		{Role: "user", Content: "What about SSNs?"},
	}

	bifrostMsgs := toBifrostMessages(original)
	if len(bifrostMsgs) != 4 {
		t.Fatalf("expected 4 messages, got %d", len(bifrostMsgs))
	}

	roles := []schemas.ChatMessageRole{
		schemas.ChatMessageRoleSystem,
		schemas.ChatMessageRoleUser,
		schemas.ChatMessageRoleAssistant,
		schemas.ChatMessageRoleUser,
	}
	for i, expected := range roles {
		if bifrostMsgs[i].Role != expected {
			t.Errorf("msg[%d] role = %q, want %q", i, bifrostMsgs[i].Role, expected)
		}
	}

	if bifrostMsgs[0].Content.ContentStr == nil || *bifrostMsgs[0].Content.ContentStr != original[0].Content {
		t.Error("system message content mismatch")
	}
}

// ---------------------------------------------------------------------------
// Bifrost request conversion: tools, stop, temperature, fallbacks
// ---------------------------------------------------------------------------

func TestBifrostE2E_RequestConversion(t *testing.T) {
	t.Run("full_request", func(t *testing.T) {
		temp := float64(0.7)
		topP := float64(0.9)
		req := &ChatRequest{
			Model:       "gpt-4",
			Messages:    []ChatMessage{{Role: "user", Content: "hi"}},
			Temperature: &temp,
			TopP:        &topP,
			MaxTokens:   intPtr(100),
			Stop:        json.RawMessage(`["END","STOP"]`),
			Tools:       json.RawMessage(`[{"type":"function","function":{"name":"get_weather"}}]`),
			Fallbacks:   []string{"anthropic/claude-3-sonnet", "bedrock/anthropic.claude-3-haiku"},
		}

		bReq := toBifrostChatRequest(schemas.OpenAI, "gpt-4", req)
		if bReq.Model != "gpt-4" {
			t.Errorf("model = %q, want gpt-4", bReq.Model)
		}
		if len(bReq.Input) != 1 {
			t.Fatalf("expected 1 message, got %d", len(bReq.Input))
		}
		if bReq.Params.Temperature == nil || *bReq.Params.Temperature != 0.7 {
			t.Error("temperature not propagated")
		}
		if bReq.Params.TopP == nil || *bReq.Params.TopP != 0.9 {
			t.Error("top_p not propagated")
		}
		if bReq.Params.MaxCompletionTokens == nil || *bReq.Params.MaxCompletionTokens != 100 {
			t.Error("max_tokens not propagated")
		}
		if len(bReq.Params.Stop) != 2 {
			t.Errorf("expected 2 stop tokens, got %d", len(bReq.Params.Stop))
		}
		if len(bReq.Params.Tools) != 1 {
			t.Errorf("expected 1 tool, got %d", len(bReq.Params.Tools))
		}
		if len(bReq.Fallbacks) != 2 {
			t.Fatalf("expected 2 fallbacks, got %d", len(bReq.Fallbacks))
		}
		if bReq.Fallbacks[0].Provider != schemas.Anthropic {
			t.Errorf("fallback[0] provider = %q, want anthropic", bReq.Fallbacks[0].Provider)
		}
		if bReq.Fallbacks[1].Provider != schemas.Bedrock {
			t.Errorf("fallback[1] provider = %q, want bedrock", bReq.Fallbacks[1].Provider)
		}
	})

	t.Run("string_stop", func(t *testing.T) {
		req := &ChatRequest{
			Model:    "gpt-4",
			Messages: []ChatMessage{{Role: "user", Content: "hi"}},
			Stop:     json.RawMessage(`"END"`),
		}
		bReq := toBifrostChatRequest(schemas.OpenAI, "gpt-4", req)
		if len(bReq.Params.Stop) != 1 || bReq.Params.Stop[0] != "END" {
			t.Errorf("string stop should produce [END], got %v", bReq.Params.Stop)
		}
	})

	t.Run("nil_optional_fields", func(t *testing.T) {
		req := &ChatRequest{
			Model:    "gpt-4",
			Messages: []ChatMessage{{Role: "user", Content: "hi"}},
		}
		bReq := toBifrostChatRequest(schemas.OpenAI, "gpt-4", req)
		if bReq.Params.Temperature != nil {
			t.Error("nil temperature should not be propagated")
		}
		if bReq.Params.MaxCompletionTokens != nil {
			t.Error("nil max_tokens should not be propagated")
		}
	})
}

// ---------------------------------------------------------------------------
// Bifrost response/stream conversion
// ---------------------------------------------------------------------------

func TestBifrostE2E_ResponseConversion(t *testing.T) {
	content := "The file contains an SSH private key."
	finishReason := "stop"
	resp := &schemas.BifrostChatResponse{
		ID:      "chatcmpl-e2e",
		Object:  "chat.completion",
		Created: 1720000000,
		Model:   "claude-sonnet-4-20250514",
		Choices: []schemas.BifrostResponseChoice{
			{
				Index:        0,
				FinishReason: &finishReason,
				ChatNonStreamResponseChoice: &schemas.ChatNonStreamResponseChoice{
					Message: &schemas.ChatMessage{
						Role:    schemas.ChatMessageRoleAssistant,
						Content: &schemas.ChatMessageContent{ContentStr: &content},
					},
				},
			},
		},
		Usage: &schemas.BifrostLLMUsage{
			PromptTokens:     15,
			CompletionTokens: 12,
			TotalTokens:      27,
		},
	}

	cr := fromBifrostChatResponse(resp)
	if cr.ID != "chatcmpl-e2e" {
		t.Errorf("ID = %q", cr.ID)
	}
	if cr.Model != "claude-sonnet-4-20250514" {
		t.Errorf("model = %q", cr.Model)
	}
	if len(cr.Choices) != 1 || cr.Choices[0].Message.Content != content {
		t.Error("content mismatch")
	}
	if cr.Usage == nil || cr.Usage.TotalTokens != 27 {
		t.Error("usage mismatch")
	}
}

func TestBifrostE2E_StreamChunkConversion(t *testing.T) {
	content := "Found"
	roleStr := string(schemas.ChatMessageRoleAssistant)
	resp := &schemas.BifrostChatResponse{
		ID:      "chunk-e2e-1",
		Object:  "chat.completion.chunk",
		Created: 1720000000,
		Model:   "gpt-4o",
		Choices: []schemas.BifrostResponseChoice{
			{
				Index: 0,
				ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{
					Delta: &schemas.ChatStreamResponseChoiceDelta{
						Role:    &roleStr,
						Content: &content,
					},
				},
			},
		},
	}

	sc := fromBifrostStreamChunk(resp)
	if sc.ID != "chunk-e2e-1" {
		t.Errorf("ID = %q", sc.ID)
	}
	if len(sc.Choices) != 1 || sc.Choices[0].Delta.Content != "Found" {
		t.Error("delta content mismatch")
	}
	if sc.Choices[0].Delta.Role != "assistant" {
		t.Error("delta role mismatch")
	}
}

// ---------------------------------------------------------------------------
// Raw content handling (multi-modal support)
// ---------------------------------------------------------------------------

func TestBifrostE2E_RawContentConversion(t *testing.T) {
	t.Run("string", func(t *testing.T) {
		raw := json.RawMessage(`"Hello world"`)
		mc := rawContentToBifrost(raw)
		if mc == nil || mc.ContentStr == nil || *mc.ContentStr != "Hello world" {
			t.Error("string content not converted")
		}
	})

	t.Run("content_blocks", func(t *testing.T) {
		raw := json.RawMessage(`[{"type":"text","text":"block one"},{"type":"image_url","image_url":{"url":"data:image/png;base64,..."}}]`)
		mc := rawContentToBifrost(raw)
		if mc == nil || mc.ContentBlocks == nil || len(mc.ContentBlocks) != 2 {
			t.Error("content blocks not converted")
		}
	})

	t.Run("nil", func(t *testing.T) {
		if rawContentToBifrost(nil) != nil {
			t.Error("nil should return nil")
		}
	})

	t.Run("empty", func(t *testing.T) {
		if rawContentToBifrost(json.RawMessage{}) != nil {
			t.Error("empty should return nil")
		}
	})

	t.Run("boolean_fallback", func(t *testing.T) {
		mc := rawContentToBifrost(json.RawMessage(`true`))
		if mc == nil || mc.ContentStr == nil || *mc.ContentStr != "true" {
			t.Error("non-string/non-array should fall back to string cast")
		}
	})
}

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

func TestBifrostE2E_UnknownProviderError(t *testing.T) {
	// "fakeprovider" is not in knownProviders, so splitModel returns
	// ("", "fakeprovider/model") and inferProvider defaults to "openai".
	// To trigger the actual "unknown provider" error, we must call
	// mapProviderKey directly with a name that isn't in the switch.
	_, err := mapProviderKey("fakeprovider")
	if err == nil {
		t.Fatal("expected error for unknown provider key")
	}
	if !strings.Contains(err.Error(), "unknown provider") {
		t.Errorf("error should contain 'unknown provider', got: %v", err)
	}
}

func TestBifrostE2E_EmptyModelProviderInference(t *testing.T) {
	p, err := NewProvider("gpt-4o", "sk-test")
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	bp := p.(*bifrostProvider)
	if bp.providerKey != schemas.OpenAI {
		t.Errorf("bare gpt-4o should infer openai, got %q", bp.providerKey)
	}
}

// ---------------------------------------------------------------------------
// Bedrock ABSK key handling
// ---------------------------------------------------------------------------

func TestBifrostE2E_BedrockABSKKeyRegistration(t *testing.T) {
	provKey := schemas.Bedrock

	bifrostAccMu.Lock()
	origAcc := bifrostAccounts[provKey]
	origUpd := bifrostUpdated[provKey]
	delete(bifrostAccounts, provKey)
	delete(bifrostUpdated, provKey)
	bifrostAccMu.Unlock()

	defer func() {
		bifrostAccMu.Lock()
		if origAcc != nil {
			bifrostAccounts[provKey] = origAcc
			bifrostUpdated[provKey] = origUpd
		} else {
			delete(bifrostAccounts, provKey)
			delete(bifrostUpdated, provKey)
		}
		bifrostAccMu.Unlock()
	}()

	registerProvider(schemas.Bedrock, "ABSKe2eTestKey123", "")

	bifrostAccMu.Lock()
	acc := bifrostAccounts[schemas.Bedrock]
	bifrostAccMu.Unlock()

	if acc == nil {
		t.Fatal("Bedrock not registered")
	}
	if acc.keys[0].Value.Val != "ABSKe2eTestKey123" {
		t.Errorf("ABSK key should be in Value, got %q", acc.keys[0].Value.Val)
	}
	if acc.keys[0].BedrockKeyConfig != nil {
		t.Error("ABSK keys should NOT have BedrockKeyConfig (IAM)")
	}
}

// ---------------------------------------------------------------------------
// Live provider integration tests (skipped without env vars)
// ---------------------------------------------------------------------------

func TestBifrostE2E_LiveOpenAI(t *testing.T) {
	apiKey := os.Getenv("OPENAI_API_KEY")
	if apiKey == "" {
		t.Skip("OPENAI_API_KEY not set — skipping live OpenAI test")
	}

	p, err := NewProvider("openai/gpt-4o-mini", apiKey)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := p.ChatCompletion(ctx, &ChatRequest{
		Model: "gpt-4o-mini",
		Messages: []ChatMessage{
			{Role: "user", Content: "Reply with exactly: BIFROST_E2E_OK"},
		},
		MaxTokens: intPtr(20),
	})
	if err != nil {
		t.Fatalf("ChatCompletion: %v", err)
	}
	if len(resp.Choices) == 0 || resp.Choices[0].Message == nil {
		t.Fatal("no response choices")
	}
	if !strings.Contains(resp.Choices[0].Message.Content, "BIFROST_E2E_OK") {
		t.Errorf("unexpected response: %q", resp.Choices[0].Message.Content)
	}
}

func TestBifrostE2E_LiveBedrock(t *testing.T) {
	apiKey := os.Getenv("BIFROST_API_KEY")
	if apiKey == "" {
		t.Skip("BIFROST_API_KEY not set — skipping live Bedrock test")
	}

	const model = "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0"
	p, err := NewProvider(model, apiKey)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := p.ChatCompletion(ctx, &ChatRequest{
		Model: model,
		Messages: []ChatMessage{
			{Role: "user", Content: "Reply with exactly: BIFROST_E2E_OK"},
		},
		MaxTokens: intPtr(20),
	})
	if err != nil {
		t.Fatalf("ChatCompletion: %v", err)
	}
	if len(resp.Choices) == 0 || resp.Choices[0].Message == nil {
		t.Fatal("no response choices")
	}
	t.Logf("Bedrock response: %s", resp.Choices[0].Message.Content)
}

func TestBifrostE2E_LiveBedrockStream(t *testing.T) {
	apiKey := os.Getenv("BIFROST_API_KEY")
	if apiKey == "" {
		t.Skip("BIFROST_API_KEY not set — skipping live Bedrock stream test")
	}

	const model = "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0"
	p, err := NewProvider(model, apiKey)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var chunks int
	var accumulated string
	usage, err := p.ChatCompletionStream(ctx, &ChatRequest{
		Model: model,
		Messages: []ChatMessage{
			{Role: "user", Content: "Say 'streaming works' and nothing else."},
		},
		MaxTokens: intPtr(20),
	}, func(chunk StreamChunk) {
		chunks++
		for _, c := range chunk.Choices {
			if c.Delta != nil {
				accumulated += c.Delta.Content
			}
		}
	})
	if err != nil {
		t.Fatalf("ChatCompletionStream: %v", err)
	}

	t.Logf("Bedrock stream: %d chunks, text=%q", chunks, accumulated)
	if chunks == 0 {
		t.Error("expected at least one stream chunk")
	}
	if accumulated == "" {
		t.Error("expected non-empty accumulated text")
	}
	if usage != nil {
		t.Logf("Usage: prompt=%d completion=%d total=%d",
			usage.PromptTokens, usage.CompletionTokens, usage.TotalTokens)
	}
}
