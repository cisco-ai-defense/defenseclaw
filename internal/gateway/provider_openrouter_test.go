package gateway

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOpenRouterProvider_Headers(t *testing.T) {
	var gotHeaders http.Header
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header
		gotBody, _ = io.ReadAll(r.Body)
		resp := ChatResponse{
			ID: "chatcmpl-test", Object: "chat.completion", Model: "anthropic/claude-opus-4-5",
			Choices: []ChatChoice{{Index: 0, Message: &ChatMessage{Role: "assistant", Content: "hi"}, FinishReason: strPtr("stop")}},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := &openrouterProvider{model: "anthropic/claude-opus-4-5", apiKey: "sk-or-test", baseURL: srv.URL}
	_, err := p.ChatCompletion(context.Background(), &ChatRequest{
		Model: "anthropic/claude-opus-4-5", Messages: []ChatMessage{{Role: "user", Content: "hello"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := gotHeaders.Get("Authorization"); got != "Bearer sk-or-test" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer sk-or-test")
	}
	if got := gotHeaders.Get("HTTP-Referer"); got != "https://github.com/defenseclaw/defenseclaw" {
		t.Errorf("HTTP-Referer = %q, want defenseclaw URL", got)
	}
	if got := gotHeaders.Get("X-Title"); got != "defenseclaw" {
		t.Errorf("X-Title = %q, want %q", got, "defenseclaw")
	}

	var body map[string]interface{}
	json.Unmarshal(gotBody, &body)
	if body["model"] != "anthropic/claude-opus-4-5" {
		t.Errorf("body model = %v, want anthropic/claude-opus-4-5", body["model"])
	}
}

func TestOpenRouterProvider_DefaultBaseURL(t *testing.T) {
	p := &openrouterProvider{model: "test", apiKey: "key"}
	got := p.effectiveBase()
	if got != "https://openrouter.ai/api" {
		t.Errorf("effectiveBase() = %q, want %q", got, "https://openrouter.ai/api")
	}
}

func TestOpenRouterProvider_CustomBaseURL(t *testing.T) {
	p := &openrouterProvider{model: "test", apiKey: "key", baseURL: "https://custom.example.com"}
	got := p.effectiveBase()
	if got != "https://custom.example.com" {
		t.Errorf("effectiveBase() = %q, want %q", got, "https://custom.example.com")
	}
}
