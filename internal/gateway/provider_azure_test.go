package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAzureProvider_AuthAndURL(t *testing.T) {
	var gotPath string
	var gotQuery string
	var gotAPIKeyHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		gotAPIKeyHeader = r.Header.Get("api-key")
		resp := ChatResponse{
			ID: "chatcmpl-test", Object: "chat.completion", Model: "gpt-4o",
			Choices: []ChatChoice{{Index: 0, Message: &ChatMessage{Role: "assistant", Content: "hi"}, FinishReason: strPtr("stop")}},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := &azureOpenAIProvider{model: "gpt-4o", apiKey: "azure-key-123", baseURL: srv.URL + "/openai/deployments/gpt4o"}
	_, err := p.ChatCompletion(context.Background(), &ChatRequest{
		Model: "gpt-4o", Messages: []ChatMessage{{Role: "user", Content: "hello"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotAPIKeyHeader != "azure-key-123" {
		t.Errorf("api-key header = %q, want %q", gotAPIKeyHeader, "azure-key-123")
	}
	if !strings.HasSuffix(gotPath, "/chat/completions") {
		t.Errorf("path = %q, want suffix /chat/completions", gotPath)
	}
	if !strings.Contains(gotQuery, "api-version=") {
		t.Errorf("query = %q, want api-version param", gotQuery)
	}
}

func TestAzureProvider_NoBearer(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		resp := ChatResponse{
			ID: "chatcmpl-test", Object: "chat.completion", Model: "gpt-4o",
			Choices: []ChatChoice{{Index: 0, Message: &ChatMessage{Role: "assistant", Content: "hi"}, FinishReason: strPtr("stop")}},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := &azureOpenAIProvider{model: "gpt-4o", apiKey: "azure-key", baseURL: srv.URL}
	p.ChatCompletion(context.Background(), &ChatRequest{
		Model: "gpt-4o", Messages: []ChatMessage{{Role: "user", Content: "test"}},
	})

	if gotAuth != "" {
		t.Errorf("Authorization header should be empty for Azure, got %q", gotAuth)
	}
}
