package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGeminiCompatProvider_DefaultBase(t *testing.T) {
	p := &geminiCompatProvider{model: "gemini-2.0-flash", apiKey: "key"}
	got := p.effectiveBase()
	if got != "https://generativelanguage.googleapis.com/v1beta/openai" {
		t.Errorf("effectiveBase() = %q, want Google compat URL", got)
	}
}

func TestGeminiCompatProvider_BearerAuth(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		resp := ChatResponse{
			ID: "chatcmpl-test", Object: "chat.completion", Model: "gemini-2.0-flash",
			Choices: []ChatChoice{{Index: 0, Message: &ChatMessage{Role: "assistant", Content: "hi"}, FinishReason: strPtr("stop")}},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := &geminiCompatProvider{model: "gemini-2.0-flash", apiKey: "AIzaTest123", baseURL: srv.URL}
	_, err := p.ChatCompletion(context.Background(), &ChatRequest{
		Model: "gemini-2.0-flash", Messages: []ChatMessage{{Role: "user", Content: "hello"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotAuth != "Bearer AIzaTest123" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer AIzaTest123")
	}
}
