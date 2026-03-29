package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// inferAPIKeyEnv
// ---------------------------------------------------------------------------

func TestInferAPIKeyEnv(t *testing.T) {
	tests := []struct {
		model   string
		wantEnv string
	}{
		{"openrouter/meta-llama/llama-3.3-70b", "OPENROUTER_API_KEY"},
		{"ollama/llama3.2", ""},
		{"anthropic/claude-opus-4-6", "ANTHROPIC_API_KEY"},
		{"openai/gpt-4o", "OPENAI_API_KEY"},
		{"gpt-4o", "OPENAI_API_KEY"}, // no prefix → default
	}

	for _, tc := range tests {
		t.Run(tc.model, func(t *testing.T) {
			got := inferAPIKeyEnv(tc.model)
			if got != tc.wantEnv {
				t.Errorf("inferAPIKeyEnv(%q) = %q, want %q", tc.model, got, tc.wantEnv)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// NewProvider routing
// ---------------------------------------------------------------------------

func TestNewProvider_Routing(t *testing.T) {
	tests := []struct {
		name        string
		model       string
		apiKey      string
		wantBaseURL string
		wantModel   string
	}{
		{
			name:        "openrouter prefix",
			model:       "openrouter/meta-llama/llama-3.3-70b-instruct",
			apiKey:      "sk-or-test",
			wantBaseURL: "https://openrouter.ai/api",
			wantModel:   "meta-llama/llama-3.3-70b-instruct",
		},
		{
			name:        "ollama prefix",
			model:       "ollama/llama3.2",
			apiKey:      "",
			wantBaseURL: "http://localhost:11434",
			wantModel:   "llama3.2",
		},
		{
			name:        "openai prefix",
			model:       "openai/gpt-4o",
			apiKey:      "sk-test",
			wantBaseURL: "https://api.openai.com",
			wantModel:   "gpt-4o",
		},
		{
			name:        "anthropic prefix",
			model:       "anthropic/claude-opus-4-6",
			apiKey:      "sk-ant-test",
			wantBaseURL: "", // anthropicProvider has no baseURL field — just verify it's not openai
			wantModel:   "claude-opus-4-6",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := NewProvider(tc.model, tc.apiKey)
			if err != nil {
				t.Fatalf("NewProvider error: %v", err)
			}
			if p == nil {
				t.Fatal("NewProvider returned nil")
			}

			if tc.wantBaseURL == "" {
				// anthropic — just ensure it's an anthropicProvider
				if _, ok := p.(*anthropicProvider); !ok {
					t.Errorf("want anthropicProvider, got %T", p)
				}
				return
			}

			op, ok := p.(*openaiProvider)
			if !ok {
				t.Fatalf("want openaiProvider, got %T", p)
			}
			if op.baseURL != tc.wantBaseURL {
				t.Errorf("baseURL = %q, want %q", op.baseURL, tc.wantBaseURL)
			}
			if op.model != tc.wantModel {
				t.Errorf("model = %q, want %q", op.model, tc.wantModel)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// inferProvider
// ---------------------------------------------------------------------------

func TestInferProvider(t *testing.T) {
	tests := []struct {
		name     string
		model    string
		apiKey   string
		wantProv string
	}{
		{"claude model name", "claude-opus-4-6", "", "anthropic"},
		{"sk-ant- key", "gpt-4", "sk-ant-abc123", "anthropic"},
		{"sk-or- key", "llama-3.3-70b", "sk-or-abc123", "openrouter"},
		{"unknown falls back to openai", "gpt-4o", "sk-test", "openai"},
		{"empty", "", "", "openai"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := inferProvider(tc.model, tc.apiKey)
			if got != tc.wantProv {
				t.Errorf("inferProvider(%q, %q) = %q, want %q", tc.model, tc.apiKey, got, tc.wantProv)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// NewProviderWithBase — base URL override
// ---------------------------------------------------------------------------

func TestNewProviderWithBase_Override(t *testing.T) {
	t.Run("custom base overrides ollama default", func(t *testing.T) {
		p := NewProviderWithBase("ollama/llama3.2", "", "http://192.168.1.100:11434")
		op, ok := p.(*openaiProvider)
		if !ok {
			t.Fatalf("want openaiProvider, got %T", p)
		}
		if op.baseURL != "http://192.168.1.100:11434" {
			t.Errorf("baseURL = %q, want custom host", op.baseURL)
		}
	})

	t.Run("custom base overrides openrouter default", func(t *testing.T) {
		p := NewProviderWithBase("openrouter/mistral/mistral-7b", "sk-or-x", "https://my-proxy.example.com")
		op, ok := p.(*openaiProvider)
		if !ok {
			t.Fatalf("want openaiProvider, got %T", p)
		}
		if op.baseURL != "https://my-proxy.example.com" {
			t.Errorf("baseURL = %q, want custom proxy", op.baseURL)
		}
	})

	t.Run("empty base falls through to NewProvider", func(t *testing.T) {
		p := NewProviderWithBase("openrouter/mistral/mistral-7b", "sk-or-x", "")
		op, ok := p.(*openaiProvider)
		if !ok {
			t.Fatalf("want openaiProvider, got %T", p)
		}
		if op.baseURL != "https://openrouter.ai/api" {
			t.Errorf("baseURL = %q, want openrouter default", op.baseURL)
		}
	})

	t.Run("trailing slash stripped", func(t *testing.T) {
		p := NewProviderWithBase("openai/gpt-4o", "sk-test", "https://my-proxy.example.com/")
		op, ok := p.(*openaiProvider)
		if !ok {
			t.Fatalf("want openaiProvider, got %T", p)
		}
		if strings.HasSuffix(op.baseURL, "/") {
			t.Errorf("baseURL %q should not have trailing slash", op.baseURL)
		}
	})
}

// ---------------------------------------------------------------------------
// HTTP-level: verify correct base URL and auth header are used
// ---------------------------------------------------------------------------

func TestOpenRouterRequestHeaders(t *testing.T) {
	var capturedAuth, capturedURL string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		capturedURL = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":      "chatcmpl-1",
			"object":  "chat.completion",
			"created": 1,
			"model":   "meta-llama/llama-3.3-70b-instruct",
			"choices": []map[string]interface{}{
				{"index": 0, "message": map[string]string{"role": "assistant", "content": "hi"}, "finish_reason": "stop"},
			},
		})
	}))
	defer srv.Close()

	p := NewProviderWithBase("openrouter/meta-llama/llama-3.3-70b-instruct", "sk-or-testkey", srv.URL)
	_, err := p.ChatCompletion(t.Context(), &ChatRequest{
		Messages: []ChatMessage{{Role: "user", Content: "hello"}},
	})
	if err != nil {
		t.Fatalf("ChatCompletion: %v", err)
	}

	if capturedAuth != "Bearer sk-or-testkey" {
		t.Errorf("Authorization = %q, want Bearer sk-or-testkey", capturedAuth)
	}
	if capturedURL != "/v1/chat/completions" {
		t.Errorf("path = %q, want /v1/chat/completions", capturedURL)
	}
}

func TestOllamaRequestHeaders(t *testing.T) {
	var capturedAuth, capturedURL string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		capturedURL = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":      "chatcmpl-1",
			"object":  "chat.completion",
			"created": 1,
			"model":   "llama3.2",
			"choices": []map[string]interface{}{
				{"index": 0, "message": map[string]string{"role": "assistant", "content": "hi"}, "finish_reason": "stop"},
			},
		})
	}))
	defer srv.Close()

	p := NewProviderWithBase("ollama/llama3.2", "", srv.URL)
	_, err := p.ChatCompletion(t.Context(), &ChatRequest{
		Messages: []ChatMessage{{Role: "user", Content: "hello"}},
	})
	if err != nil {
		t.Fatalf("ChatCompletion: %v", err)
	}

	// Ollama has no key — Authorization header is "Bearer" (empty bearer token).
	if capturedAuth != "Bearer" && capturedAuth != "Bearer " {
		t.Errorf("Authorization = %q, want empty bearer for Ollama", capturedAuth)
	}
	if capturedURL != "/v1/chat/completions" {
		t.Errorf("path = %q, want /v1/chat/completions", capturedURL)
	}
}

func TestOpenRouterStreamingRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"meta-llama/llama-3.3-70b-instruct\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"hi\"},\"finish_reason\":null}]}\n\n")
		io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer srv.Close()

	p := NewProviderWithBase("openrouter/meta-llama/llama-3.3-70b-instruct", "sk-or-testkey", srv.URL)

	var chunks []StreamChunk
	usage, err := p.ChatCompletionStream(t.Context(), &ChatRequest{
		Messages: []ChatMessage{{Role: "user", Content: "hello"}},
	}, func(c StreamChunk) {
		chunks = append(chunks, c)
	})
	if err != nil {
		t.Fatalf("ChatCompletionStream: %v", err)
	}
	_ = usage

	if len(chunks) == 0 {
		t.Error("expected at least one streaming chunk")
	}
}

func TestOllamaCustomHostRouting(t *testing.T) {
	// Verify that a custom base_url overrides the localhost default for Ollama.
	custom := "http://192.168.1.50:11434"
	p := NewProviderWithBase("ollama/qwen2.5", "", custom)
	op, ok := p.(*openaiProvider)
	if !ok {
		t.Fatalf("want openaiProvider, got %T", p)
	}
	if op.baseURL != custom {
		t.Errorf("baseURL = %q, want %q", op.baseURL, custom)
	}
	if op.model != "qwen2.5" {
		t.Errorf("model = %q, want qwen2.5", op.model)
	}
}

func TestAPIKeyPassThrough(t *testing.T) {
	t.Run("openai_uses_request_key_when_set", func(t *testing.T) {
		var capturedAuth string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedAuth = r.Header.Get("Authorization")
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id": "chatcmpl-1", "object": "chat.completion", "created": 1,
				"model": "gpt-4o",
				"choices": []map[string]interface{}{
					{"index": 0, "message": map[string]string{"role": "assistant", "content": "hi"}, "finish_reason": "stop"},
				},
			})
		}))
		defer srv.Close()

		p := &openaiProvider{model: "gpt-4o", apiKey: "static-key", baseURL: srv.URL}
		req := &ChatRequest{
			Messages: []ChatMessage{{Role: "user", Content: "hello"}},
			APIKey:   "pass-through-key",
		}
		_, err := p.ChatCompletion(t.Context(), req)
		if err != nil {
			t.Fatalf("ChatCompletion error: %v", err)
		}
		if capturedAuth != "Bearer pass-through-key" {
			t.Errorf("Authorization = %q, want Bearer pass-through-key", capturedAuth)
		}
	})

	t.Run("openai_falls_back_to_static_key_when_request_key_empty", func(t *testing.T) {
		var capturedAuth string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedAuth = r.Header.Get("Authorization")
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id": "chatcmpl-1", "object": "chat.completion", "created": 1,
				"model": "gpt-4o",
				"choices": []map[string]interface{}{
					{"index": 0, "message": map[string]string{"role": "assistant", "content": "hi"}, "finish_reason": "stop"},
				},
			})
		}))
		defer srv.Close()

		p := &openaiProvider{model: "gpt-4o", apiKey: "static-key", baseURL: srv.URL}
		req := &ChatRequest{
			Messages: []ChatMessage{{Role: "user", Content: "hello"}},
			APIKey:   "",
		}
		_, err := p.ChatCompletion(t.Context(), req)
		if err != nil {
			t.Fatalf("ChatCompletion error: %v", err)
		}
		if capturedAuth != "Bearer static-key" {
			t.Errorf("Authorization = %q, want Bearer static-key", capturedAuth)
		}
	})

	t.Run("anthropic_uses_request_key_when_set", func(t *testing.T) {
		var capturedAPIKey string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedAPIKey = r.Header.Get("x-api-key")
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id":      "msg_01",
				"type":    "message",
				"role":    "assistant",
				"content": []map[string]interface{}{{"type": "text", "text": "hi"}},
				"model":   "claude-opus-4-6",
				"stop_reason": "end_turn",
				"usage": map[string]int{"input_tokens": 5, "output_tokens": 2},
			})
		}))
		defer srv.Close()

		p := &anthropicProvider{model: "claude-opus-4-6", apiKey: "static-ant-key", baseURL: srv.URL}
		req := &ChatRequest{
			Messages: []ChatMessage{{Role: "user", Content: "hello"}},
			APIKey:   "pass-through-ant-key",
		}
		_, err := p.ChatCompletion(t.Context(), req)
		if err != nil {
			t.Fatalf("anthropicProvider ChatCompletion error: %v", err)
		}
		if capturedAPIKey != "pass-through-ant-key" {
			t.Errorf("x-api-key = %q, want pass-through-ant-key", capturedAPIKey)
		}
	})
}

func TestAzureProvider(t *testing.T) {
	var capturedAPIKey, capturedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAPIKey = r.Header.Get("api-key")
		capturedPath = r.URL.Path + "?" + r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id": "chatcmpl-1", "object": "chat.completion", "created": 1,
			"model": "gpt-4o",
			"choices": []map[string]interface{}{
				{"index": 0, "message": map[string]string{"role": "assistant", "content": "hi"}, "finish_reason": "stop"},
			},
		})
	}))
	defer srv.Close()

	t.Run("uses_api_key_header_not_bearer", func(t *testing.T) {
		p := &azureProvider{
			deployment: "my-gpt4o",
			apiKey:     "static-azure-key",
			baseURL:    srv.URL,
			apiVersion: "2024-02-01",
		}
		req := &ChatRequest{
			Messages: []ChatMessage{{Role: "user", Content: "hello"}},
			APIKey:   "pass-through-azure-key",
		}
		_, err := p.ChatCompletion(t.Context(), req)
		if err != nil {
			t.Fatalf("ChatCompletion error: %v", err)
		}
		if capturedAPIKey != "pass-through-azure-key" {
			t.Errorf("api-key = %q, want pass-through-azure-key", capturedAPIKey)
		}
		if !strings.Contains(capturedPath, "api-version=2024-02-01") {
			t.Errorf("path %q missing api-version param", capturedPath)
		}
	})
}

func TestNewProvider_Azure(t *testing.T) {
	p, err := NewProvider("azure/my-gpt4o", "azure-key")
	if err != nil {
		t.Fatalf("NewProvider error: %v", err)
	}
	ap, ok := p.(*azureProvider)
	if !ok {
		t.Fatalf("want azureProvider, got %T", p)
	}
	if ap.deployment != "my-gpt4o" {
		t.Errorf("deployment = %q, want my-gpt4o", ap.deployment)
	}
	if ap.apiVersion != "2024-02-01" {
		t.Errorf("apiVersion = %q, want 2024-02-01", ap.apiVersion)
	}
}

func TestProxyExtractsAPIKeyFromAuthHeader(t *testing.T) {
	var capturedKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedKey = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id": "chatcmpl-1", "object": "chat.completion", "created": 1,
			"model": "gpt-4o",
			"choices": []map[string]interface{}{
				{"index": 0, "message": map[string]string{"role": "assistant", "content": "hi"}, "finish_reason": "stop"},
			},
		})
	}))
	defer srv.Close()

	realProvider := &openaiProvider{model: "gpt-4o", apiKey: "static-key", baseURL: srv.URL}
	insp := newMockInspector()
	proxy := newTestProxy(t, realProvider, insp, "observe")
	// Make the request look like it comes from loopback so auth passes
	reqBody := mustJSON(t, map[string]interface{}{
		"model":    "gpt-4o",
		"messages": []map[string]interface{}{{"role": "user", "content": "Hello"}},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer sk-or-passthrough-key")
	req.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()
	proxy.handleChatCompletion(rec, req)

	if capturedKey != "Bearer sk-or-passthrough-key" {
		t.Errorf("upstream Authorization = %q, want Bearer sk-or-passthrough-key", capturedKey)
	}
}

// ---------------------------------------------------------------------------
// Google Gemini via OpenAI-compatible endpoint
// ---------------------------------------------------------------------------

func TestNewProvider_Gemini(t *testing.T) {
	tests := []struct {
		model       string
		wantBaseURL string
	}{
		{"google/gemini-2.0-flash", "https://generativelanguage.googleapis.com/v1beta/openai"},
		{"gemini/gemini-2.0-flash", "https://generativelanguage.googleapis.com/v1beta/openai"},
	}
	for _, tc := range tests {
		t.Run(tc.model, func(t *testing.T) {
			p, err := NewProvider(tc.model, "google-key")
			if err != nil {
				t.Fatalf("NewProvider(%q) error: %v", tc.model, err)
			}
			op, ok := p.(*openaiProvider)
			if !ok {
				t.Fatalf("want openaiProvider, got %T", p)
			}
			if op.baseURL != tc.wantBaseURL {
				t.Errorf("baseURL = %q, want %q", op.baseURL, tc.wantBaseURL)
			}
		})
	}
}

func TestInferProvider_Gemini(t *testing.T) {
	got := inferProvider("gemini-2.0-flash", "")
	if got != "google" {
		t.Errorf("inferProvider(gemini-*) = %q, want google", got)
	}
}

// ---------------------------------------------------------------------------
// Amazon Bedrock provider
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Provider matrix — all 8 providers in one table
// ---------------------------------------------------------------------------

func TestNewProvider_AllProviders(t *testing.T) {
	tests := []struct {
		model     string
		apiKey    string
		wantType  string
		wantField string // for openaiProvider: check baseURL; for others: just type
	}{
		{"openrouter/meta-llama/llama-3.3-70b", "sk-or-key", "openai", "https://openrouter.ai/api"},
		{"openai/gpt-4o", "sk-key", "openai", "https://api.openai.com"},
		{"anthropic/claude-opus-4-6", "sk-ant-key", "anthropic", ""},
		{"ollama/llama3.2:3b", "", "openai", "http://localhost:11434"},
		{"google/gemini-2.0-flash", "google-key", "openai", "https://generativelanguage.googleapis.com/v1beta/openai"},
		{"gemini/gemini-2.0-flash", "google-key", "openai", "https://generativelanguage.googleapis.com/v1beta/openai"},
		{"azure/my-deployment", "azure-key", "azure", ""},
		{"bedrock/anthropic.claude-3-5-sonnet-20241022-v2:0", "", "bedrock", ""},
	}
	for _, tc := range tests {
		t.Run(tc.model, func(t *testing.T) {
			p, err := NewProvider(tc.model, tc.apiKey)
			if err != nil {
				t.Fatalf("NewProvider(%q) error: %v", tc.model, err)
			}
			switch tc.wantType {
			case "openai":
				op, ok := p.(*openaiProvider)
				if !ok {
					t.Fatalf("want openaiProvider, got %T", p)
				}
				if tc.wantField != "" && op.baseURL != tc.wantField {
					t.Errorf("baseURL = %q, want %q", op.baseURL, tc.wantField)
				}
			case "anthropic":
				if _, ok := p.(*anthropicProvider); !ok {
					t.Fatalf("want anthropicProvider, got %T", p)
				}
			case "azure":
				if _, ok := p.(*azureProvider); !ok {
					t.Fatalf("want azureProvider, got %T", p)
				}
			case "bedrock":
				if _, ok := p.(*bedrockProvider); !ok {
					t.Fatalf("want bedrockProvider, got %T", p)
				}
			}
		})
	}
}

func TestNewProvider_Bedrock(t *testing.T) {
	t.Run("creates_bedrock_provider", func(t *testing.T) {
		p, err := NewProvider("bedrock/anthropic.claude-3-5-sonnet-20241022-v2:0", "")
		if err != nil {
			t.Fatalf("NewProvider bedrock error: %v", err)
		}
		bp, ok := p.(*bedrockProvider)
		if !ok {
			t.Fatalf("want bedrockProvider, got %T", p)
		}
		if bp.modelID != "anthropic.claude-3-5-sonnet-20241022-v2:0" {
			t.Errorf("modelID = %q", bp.modelID)
		}
	})

	t.Run("defaults_region_to_us_east_1", func(t *testing.T) {
		// Unset AWS_REGION to test default
		orig := os.Getenv("AWS_REGION")
		origDef := os.Getenv("AWS_DEFAULT_REGION")
		os.Unsetenv("AWS_REGION")
		os.Unsetenv("AWS_DEFAULT_REGION")
		defer func() {
			os.Setenv("AWS_REGION", orig)
			os.Setenv("AWS_DEFAULT_REGION", origDef)
		}()

		p, err := NewProvider("bedrock/anthropic.claude-3-5-sonnet-20241022-v2:0", "")
		if err != nil {
			t.Fatalf("NewProvider bedrock error: %v", err)
		}
		bp := p.(*bedrockProvider)
		if bp.region != "us-east-1" {
			t.Errorf("region = %q, want us-east-1", bp.region)
		}
	})
}
