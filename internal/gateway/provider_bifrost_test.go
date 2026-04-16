package gateway

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

func TestBifrostProvider_Creation(t *testing.T) {
	tests := []struct {
		name        string
		model       string
		apiKey      string
		baseURL     string
		wantProvider schemas.ModelProvider
		wantModel   string
	}{
		{
			name:         "bedrock_explicit",
			model:        "bedrock/us.anthropic.claude-3-5-haiku-20241022-v1:0",
			apiKey:       "ABSKtest123",
			wantProvider: schemas.Bedrock,
			wantModel:    "us.anthropic.claude-3-5-haiku-20241022-v1:0",
		},
		{
			// OpenClaw's stock provider name is "amazon-bedrock" (see
			// https://docs.openclaw.ai/providers/bedrock). The guardrail
			// sidecar must accept that literal prefix and route it to the
			// same Bifrost Bedrock backend as "bedrock/…".
			name:         "amazon_bedrock_openclaw_prefix",
			model:        "amazon-bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0",
			apiKey:       "ABSKtest123",
			wantProvider: schemas.Bedrock,
			wantModel:    "us.anthropic.claude-haiku-4-5-20251001-v1:0",
		},
		{
			name:         "bedrock_inferred_from_absk",
			model:        "us.anthropic.claude-3-5-haiku-20241022-v1:0",
			apiKey:       "ABSKtest123",
			wantProvider: schemas.Bedrock,
			wantModel:    "us.anthropic.claude-3-5-haiku-20241022-v1:0",
		},
		{
			name:         "anthropic_explicit",
			model:        "anthropic/claude-haiku-4-5",
			apiKey:       "sk-ant-test",
			wantProvider: schemas.Anthropic,
			wantModel:    "claude-haiku-4-5",
		},
		{
			name:         "openai_default",
			model:        "gpt-4",
			apiKey:       "sk-test",
			wantProvider: schemas.OpenAI,
			wantModel:    "gpt-4",
		},
		{
			name:         "with_base_url",
			model:        "anthropic/claude-haiku-4-5",
			apiKey:       "sk-test",
			baseURL:      "http://localhost:8080/v1",
			wantProvider: schemas.Anthropic,
			wantModel:    "claude-haiku-4-5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var p LLMProvider
			if tt.baseURL != "" {
				var err error
				p, err = NewProviderWithBase(tt.model, tt.apiKey, tt.baseURL)
				if err != nil {
					t.Fatalf("NewProviderWithBase: %v", err)
				}
			} else {
				var err error
				p, err = NewProvider(tt.model, tt.apiKey)
				if err != nil {
					t.Fatalf("NewProvider: %v", err)
				}
			}
			bp, ok := p.(*bifrostProvider)
			if !ok {
				t.Fatalf("expected *bifrostProvider, got %T", p)
			}
			if bp.providerKey != tt.wantProvider {
				t.Errorf("provider = %q, want %q", bp.providerKey, tt.wantProvider)
			}
			if bp.model != tt.wantModel {
				t.Errorf("model = %q, want %q", bp.model, tt.wantModel)
			}
			if tt.baseURL != "" && bp.baseURL != tt.baseURL {
				t.Errorf("baseURL = %q, want %q", bp.baseURL, tt.baseURL)
			}
		})
	}
}

func TestBifrostProvider_ABSKKeyDetection(t *testing.T) {
	if !isBedrockAPIKey("ABSKQmVkcm9ja0FQSUtleS15Mm9v") {
		t.Error("expected ABSK-prefixed key to be detected as Bedrock API key")
	}
	if isBedrockAPIKey("sk-ant-test") {
		t.Error("expected non-ABSK key to not be detected as Bedrock API key")
	}
	if isBedrockAPIKey("sk-test") {
		t.Error("expected OpenAI key to not be detected as Bedrock API key")
	}
}

func TestBifrostProvider_RegisterProvider(t *testing.T) {
	bifrostAccMu.Lock()
	delete(bifrostAccounts, schemas.ModelProvider("test-provider"))
	bifrostAccMu.Unlock()

	registerProvider("test-provider", "test-key-123", "")

	bifrostAccMu.Lock()
	acc, ok := bifrostAccounts["test-provider"]
	bifrostAccMu.Unlock()

	if !ok {
		t.Fatal("expected provider to be registered")
	}
	if len(acc.keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(acc.keys))
	}
	if acc.keys[0].Value.Val != "test-key-123" {
		t.Errorf("key value = %q, want test-key-123", acc.keys[0].Value.Val)
	}

	bifrostAccMu.Lock()
	delete(bifrostAccounts, schemas.ModelProvider("test-provider"))
	bifrostAccMu.Unlock()
}

func TestBifrostProvider_RegisterBedrockWithABSK(t *testing.T) {
	bifrostAccMu.Lock()
	delete(bifrostAccounts, schemas.Bedrock)
	bifrostAccMu.Unlock()

	registerProvider(schemas.Bedrock, "ABSKtest123", "")

	bifrostAccMu.Lock()
	acc := bifrostAccounts[schemas.Bedrock]
	bifrostAccMu.Unlock()

	if acc == nil {
		t.Fatal("expected bedrock provider to be registered")
	}
	key := acc.keys[0]
	if key.Value.Val != "ABSKtest123" {
		t.Errorf("ABSK key should be set as Value, got %q", key.Value.Val)
	}
	if key.BedrockKeyConfig != nil {
		t.Error("ABSK keys should NOT have BedrockKeyConfig (IAM) set")
	}

	bifrostAccMu.Lock()
	delete(bifrostAccounts, schemas.Bedrock)
	bifrostAccMu.Unlock()
}

func TestBifrostProvider_MessageConversion(t *testing.T) {
	msgs := []ChatMessage{
		{Role: "system", Content: "You are a helpful assistant."},
		{Role: "user", Content: "Hello"},
		{Role: "assistant", Content: "Hi there!"},
	}

	bMsgs := toBifrostMessages(msgs)
	if len(bMsgs) != 3 {
		t.Fatalf("expected 3 messages, got %d", len(bMsgs))
	}

	if bMsgs[0].Role != schemas.ChatMessageRoleSystem {
		t.Errorf("msg[0] role = %q, want system", bMsgs[0].Role)
	}
	if bMsgs[0].Content == nil || bMsgs[0].Content.ContentStr == nil || *bMsgs[0].Content.ContentStr != "You are a helpful assistant." {
		t.Error("msg[0] content mismatch")
	}

	if bMsgs[1].Role != schemas.ChatMessageRoleUser {
		t.Errorf("msg[1] role = %q, want user", bMsgs[1].Role)
	}
}

func TestBifrostProvider_ResponseConversion(t *testing.T) {
	content := "Hello from Bifrost!"
	resp := &schemas.BifrostChatResponse{
		ID:      "chatcmpl-test",
		Object:  "chat.completion",
		Created: 1234567890,
		Model:   "claude-3-5-haiku",
		Choices: []schemas.BifrostResponseChoice{
			{
				Index: 0,
				ChatNonStreamResponseChoice: &schemas.ChatNonStreamResponseChoice{
					Message: &schemas.ChatMessage{
						Role:    schemas.ChatMessageRoleAssistant,
						Content: &schemas.ChatMessageContent{ContentStr: &content},
					},
				},
			},
		},
		Usage: &schemas.BifrostLLMUsage{
			PromptTokens:     10,
			CompletionTokens: 5,
			TotalTokens:      15,
		},
	}

	cr := fromBifrostChatResponse(resp)
	if cr.ID != "chatcmpl-test" {
		t.Errorf("ID = %q, want chatcmpl-test", cr.ID)
	}
	if len(cr.Choices) != 1 {
		t.Fatalf("expected 1 choice, got %d", len(cr.Choices))
	}
	if cr.Choices[0].Message == nil {
		t.Fatal("expected message in choice")
	}
	if cr.Choices[0].Message.Content != "Hello from Bifrost!" {
		t.Errorf("content = %q, want 'Hello from Bifrost!'", cr.Choices[0].Message.Content)
	}
	if cr.Usage.TotalTokens != 15 {
		t.Errorf("total tokens = %d, want 15", cr.Usage.TotalTokens)
	}
}

func TestBifrostProvider_StreamChunkConversion(t *testing.T) {
	content := "Hello"
	finishReason := "stop"
	roleStr := string(schemas.ChatMessageRoleAssistant)

	resp := &schemas.BifrostChatResponse{
		ID:      "chunk-1",
		Object:  "chat.completion.chunk",
		Created: 1234567890,
		Model:   "test-model",
		Choices: []schemas.BifrostResponseChoice{
			{
				Index:        0,
				FinishReason: &finishReason,
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
	if sc.ID != "chunk-1" {
		t.Errorf("ID = %q, want chunk-1", sc.ID)
	}
	if len(sc.Choices) != 1 {
		t.Fatalf("expected 1 choice, got %d", len(sc.Choices))
	}
	if sc.Choices[0].Delta == nil {
		t.Fatal("expected delta in choice")
	}
	if sc.Choices[0].Delta.Content != "Hello" {
		t.Errorf("delta content = %q, want 'Hello'", sc.Choices[0].Delta.Content)
	}
	if sc.Choices[0].Delta.Role != "assistant" {
		t.Errorf("delta role = %q, want 'assistant'", sc.Choices[0].Delta.Role)
	}
}

func TestBifrostProvider_FallbackConversion(t *testing.T) {
	req := &ChatRequest{
		Model:    "test-model",
		Messages: []ChatMessage{{Role: "user", Content: "hi"}},
		Fallbacks: []string{
			"anthropic/claude-3-sonnet",
			"bedrock/us.anthropic.claude-3-5-haiku-20241022-v1:0",
		},
	}

	bReq := toBifrostChatRequest(schemas.OpenAI, "test-model", req)
	if len(bReq.Fallbacks) != 2 {
		t.Fatalf("expected 2 fallbacks, got %d", len(bReq.Fallbacks))
	}
	if bReq.Fallbacks[0].Provider != schemas.Anthropic {
		t.Errorf("fallback[0] provider = %q, want anthropic", bReq.Fallbacks[0].Provider)
	}
	if bReq.Fallbacks[0].Model != "claude-3-sonnet" {
		t.Errorf("fallback[0] model = %q, want claude-3-sonnet", bReq.Fallbacks[0].Model)
	}
	if bReq.Fallbacks[1].Provider != schemas.Bedrock {
		t.Errorf("fallback[1] provider = %q, want bedrock", bReq.Fallbacks[1].Provider)
	}
}

// TestBifrostProvider_LiveBedrock tests the actual Bifrost SDK → Bedrock flow.
// Skipped unless BIFROST_API_KEY is set.
func TestBifrostProvider_LiveBedrock(t *testing.T) {
	apiKey := os.Getenv("BIFROST_API_KEY")
	if apiKey == "" {
		t.Skip("BIFROST_API_KEY not set — skipping live Bedrock test")
	}

	p, err := NewProvider("bedrock/us.anthropic.claude-3-5-haiku-20241022-v1:0", apiKey)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := p.ChatCompletion(ctx, &ChatRequest{
		Model: "us.anthropic.claude-3-5-haiku-20241022-v1:0",
		Messages: []ChatMessage{
			{Role: "user", Content: "Say 'hello' and nothing else."},
		},
	})
	if err != nil {
		t.Fatalf("ChatCompletion: %v", err)
	}

	if len(resp.Choices) == 0 {
		t.Fatal("expected at least one choice")
	}
	t.Logf("Bedrock response: %s", resp.Choices[0].Message.Content)
}

// TestBifrostProvider_LiveBedrockStream tests streaming via Bifrost → Bedrock.
// Skipped unless BIFROST_API_KEY is set.
func TestBifrostProvider_LiveBedrockStream(t *testing.T) {
	apiKey := os.Getenv("BIFROST_API_KEY")
	if apiKey == "" {
		t.Skip("BIFROST_API_KEY not set — skipping live Bedrock stream test")
	}

	p, err := NewProvider("bedrock/us.anthropic.claude-3-5-haiku-20241022-v1:0", apiKey)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var chunks int
	var accumulated string
	usage, err := p.ChatCompletionStream(ctx, &ChatRequest{
		Model: "us.anthropic.claude-3-5-haiku-20241022-v1:0",
		Messages: []ChatMessage{
			{Role: "user", Content: "Say 'streaming works' and nothing else."},
		},
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
		t.Logf("Usage: prompt=%d completion=%d total=%d", usage.PromptTokens, usage.CompletionTokens, usage.TotalTokens)
	}
}

func TestBifrostProvider_RawContentToBifrost(t *testing.T) {
	t.Run("string_content", func(t *testing.T) {
		raw := json.RawMessage(`"hello world"`)
		mc := rawContentToBifrost(raw)
		if mc == nil || mc.ContentStr == nil || *mc.ContentStr != "hello world" {
			t.Error("expected string content")
		}
	})

	t.Run("array_content_blocks", func(t *testing.T) {
		raw := json.RawMessage(`[{"type":"text","text":"block one"},{"type":"image_url","image_url":{"url":"data:..."}}]`)
		mc := rawContentToBifrost(raw)
		if mc == nil || mc.ContentBlocks == nil {
			t.Fatal("expected content blocks")
		}
		if len(mc.ContentBlocks) != 2 {
			t.Errorf("expected 2 blocks, got %d", len(mc.ContentBlocks))
		}
	})

	t.Run("empty_input", func(t *testing.T) {
		mc := rawContentToBifrost(nil)
		if mc != nil {
			t.Error("nil input should return nil")
		}
		mc = rawContentToBifrost(json.RawMessage{})
		if mc != nil {
			t.Error("empty input should return nil")
		}
	})

	t.Run("plain_text_fallback", func(t *testing.T) {
		raw := json.RawMessage(`true`)
		mc := rawContentToBifrost(raw)
		if mc == nil || mc.ContentStr == nil || *mc.ContentStr != "true" {
			t.Error("non-string/non-array should fall back to string cast")
		}
	})
}

func TestBifrostProvider_ToolsConversion(t *testing.T) {
	req := &ChatRequest{
		Model:    "test-model",
		Messages: []ChatMessage{{Role: "user", Content: "hi"}},
		Tools:    json.RawMessage(`[{"type":"function","function":{"name":"get_weather","description":"Get weather","parameters":{"type":"object","properties":{"city":{"type":"string"}}}}}]`),
		ToolChoice: json.RawMessage(`{"type":"function","function":{"name":"get_weather"}}`),
	}

	bReq := toBifrostChatRequest(schemas.OpenAI, "test-model", req)
	if len(bReq.Params.Tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(bReq.Params.Tools))
	}
	if bReq.Params.ToolChoice == nil {
		t.Fatal("expected ToolChoice to be set")
	}
}

func TestBifrostProvider_StopConversion(t *testing.T) {
	t.Run("string_stop", func(t *testing.T) {
		req := &ChatRequest{
			Model:    "test-model",
			Messages: []ChatMessage{{Role: "user", Content: "hi"}},
			Stop:     json.RawMessage(`"END"`),
		}
		bReq := toBifrostChatRequest(schemas.OpenAI, "test-model", req)
		if len(bReq.Params.Stop) != 1 || bReq.Params.Stop[0] != "END" {
			t.Errorf("expected [END], got %v", bReq.Params.Stop)
		}
	})

	t.Run("array_stop", func(t *testing.T) {
		req := &ChatRequest{
			Model:    "test-model",
			Messages: []ChatMessage{{Role: "user", Content: "hi"}},
			Stop:     json.RawMessage(`["END","STOP"]`),
		}
		bReq := toBifrostChatRequest(schemas.OpenAI, "test-model", req)
		if len(bReq.Params.Stop) != 2 {
			t.Errorf("expected 2 stop tokens, got %d", len(bReq.Params.Stop))
		}
	})
}

func TestNewProvider_UnknownProvider(t *testing.T) {
	_, err := mapProviderKey("fakeprovider")
	if err == nil {
		t.Fatal("expected error for unknown provider")
	}
	if !strings.Contains(err.Error(), "unknown provider") {
		t.Errorf("error should mention 'unknown provider', got: %v", err)
	}
}

func TestMapProviderKey_AllKnownProviders(t *testing.T) {
	known := []string{
		"openai", "anthropic", "bedrock", "amazon-bedrock", "azure", "gemini",
		"gemini-openai", "openrouter", "groq", "mistral", "ollama",
		"vertex", "cohere", "perplexity", "cerebras", "fireworks",
		"xai", "huggingface", "replicate", "vllm",
	}
	for _, name := range known {
		_, err := mapProviderKey(name)
		if err != nil {
			t.Errorf("mapProviderKey(%q) should succeed, got: %v", name, err)
		}
	}
}

func TestBifrostProvider_RegisterUpdatesKey(t *testing.T) {
	provKey := schemas.ModelProvider("test-update-provider")

	bifrostAccMu.Lock()
	delete(bifrostAccounts, provKey)
	delete(bifrostUpdated, provKey)
	bifrostAccMu.Unlock()

	changed := registerProvider(provKey, "key-1", "")
	if !changed {
		t.Error("first registration should report changed")
	}

	changed = registerProvider(provKey, "key-1", "")
	if changed {
		t.Error("same key should not report changed")
	}

	changed = registerProvider(provKey, "key-2", "")
	if !changed {
		t.Error("different key should report changed")
	}

	bifrostAccMu.Lock()
	acc := bifrostAccounts[provKey]
	bifrostAccMu.Unlock()

	if acc.keys[0].Value.Val != "key-2" {
		t.Errorf("key should be updated to key-2, got %q", acc.keys[0].Value.Val)
	}

	changed = registerProvider(provKey, "key-2", "http://custom:8080")
	if !changed {
		t.Error("different baseURL should report changed")
	}

	bifrostAccMu.Lock()
	updatedAcc := bifrostAccounts[provKey]
	if updatedAcc.config.NetworkConfig.BaseURL != "http://custom:8080" {
		t.Errorf("baseURL should be updated, got %q", updatedAcc.config.NetworkConfig.BaseURL)
	}
	delete(bifrostAccounts, provKey)
	delete(bifrostUpdated, provKey)
	bifrostAccMu.Unlock()
}

func TestMapProviderKey_UnknownReturnsError(t *testing.T) {
	_, err := mapProviderKey("notreal")
	if err == nil {
		t.Fatal("expected error for unknown provider")
	}
	if !strings.Contains(err.Error(), "notreal") {
		t.Errorf("error should contain provider name, got: %v", err)
	}
}
