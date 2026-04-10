package connector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestInferProviderFromModel(t *testing.T) {
	tests := []struct {
		model string
		want  string
	}{
		{"gpt-4o", "openai"},
		{"gpt-4o-mini", "openai"},
		{"o1-preview", "openai"},
		{"o3-mini", "openai"},
		{"o4-mini", "openai"},
		{"claude-sonnet-4-20250514", "anthropic"},
		{"claude-opus-4-20250514", "anthropic"},
		{"gemini-2.0-flash", "gemini"},
		{"command-r-plus", "cohere"},
		{"mistral-large-latest", "mistral"},
		{"llama-3.1-70b", "meta"},
		{"deepseek-chat", "deepseek"},
		{"chatgpt-4o-latest", "openai"},
		// Explicit provider/model format.
		{"anthropic/claude-sonnet-4-20250514", "anthropic"},
		{"openai/gpt-4o", "openai"},
		{"openrouter/auto", "openrouter"},
		// Unknown model.
		{"unknown-model", ""},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.model, func(t *testing.T) {
			got := InferProviderFromModel(tt.model)
			if got != tt.want {
				t.Errorf("InferProviderFromModel(%q) = %q, want %q", tt.model, got, tt.want)
			}
		})
	}
}

func TestZeptoClawDetect(t *testing.T) {
	c := NewZeptoClawConnector("", "", nil)

	tests := []struct {
		name    string
		headers map[string]string
		want    bool
	}{
		{
			name:    "X-ZC-Provider header",
			headers: map[string]string{"X-ZC-Provider": "openai"},
			want:    true,
		},
		{
			name:    "standard Authorization (no X-DC-Target-URL)",
			headers: map[string]string{"Authorization": "Bearer sk-test"},
			want:    true,
		},
		{
			name:    "x-api-key (Anthropic style, no X-DC-Target-URL)",
			headers: map[string]string{"x-api-key": "sk-ant-key"},
			want:    true,
		},
		{
			name:    "api-key (Azure style, no X-DC-Target-URL)",
			headers: map[string]string{"api-key": "az-key"},
			want:    true,
		},
		{
			name:    "has X-DC-Target-URL — belongs to OpenClaw",
			headers: map[string]string{"X-DC-Target-URL": "https://api.openai.com", "Authorization": "Bearer sk-test"},
			want:    false,
		},
		{
			name:    "no auth headers at all",
			headers: map[string]string{},
			want:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			if got := c.Detect(req); got != tt.want {
				t.Errorf("Detect() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestZeptoClawAuthenticate(t *testing.T) {
	tests := []struct {
		name         string
		gatewayToken string
		masterKey    string
		headers      map[string]string
		remoteAddr   string
		want         bool
	}{
		{
			name:         "valid X-DC-Auth token",
			gatewayToken: "zc-token",
			headers:      map[string]string{"X-DC-Auth": "Bearer zc-token"},
			remoteAddr:   "192.168.1.1:1234",
			want:         true,
		},
		{
			name:       "loopback without token",
			remoteAddr: "127.0.0.1:1234",
			want:       true,
		},
		{
			name:         "loopback with token requires auth",
			gatewayToken: "zc-token",
			remoteAddr:   "127.0.0.1:1234",
			want:         false,
		},
		{
			name:       "no auth configured (open)",
			remoteAddr: "192.168.1.1:1234",
			want:       true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewZeptoClawConnector(tt.gatewayToken, tt.masterKey, nil)
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
			req.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			if got := c.Authenticate(req); got != tt.want {
				t.Errorf("Authenticate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestZeptoClawRoute(t *testing.T) {
	t.Run("infer provider from model prefix", func(t *testing.T) {
		c := NewZeptoClawConnector("", "", nil)
		body := `{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}],"stream":true}`
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer sk-real-key")

		decision, err := c.Route(req, []byte(body))
		if err != nil {
			t.Fatalf("Route() error: %v", err)
		}

		if decision.ProviderName != "openai" {
			t.Errorf("ProviderName = %q, want openai", decision.ProviderName)
		}
		if !strings.Contains(decision.UpstreamURL, "api.openai.com") {
			t.Errorf("UpstreamURL = %q, want to contain api.openai.com", decision.UpstreamURL)
		}
		if !strings.HasSuffix(decision.UpstreamURL, "/v1/chat/completions") {
			t.Errorf("UpstreamURL = %q, want to end with /v1/chat/completions", decision.UpstreamURL)
		}
		if decision.APIKey != "sk-real-key" {
			t.Errorf("APIKey = %q, want sk-real-key", decision.APIKey)
		}
		if decision.Model != "gpt-4o" {
			t.Errorf("Model = %q, want gpt-4o", decision.Model)
		}
		if !decision.Stream {
			t.Error("Stream should be true")
		}
		if decision.ConnectorName != "zeptoclaw" {
			t.Errorf("ConnectorName = %q", decision.ConnectorName)
		}
	})

	t.Run("explicit X-ZC-Provider header", func(t *testing.T) {
		c := NewZeptoClawConnector("", "", nil)
		body := `{"model":"my-custom-model","messages":[{"role":"user","content":"hi"}]}`
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer sk-key")
		req.Header.Set("X-ZC-Provider", "openai")

		decision, err := c.Route(req, []byte(body))
		if err != nil {
			t.Fatalf("Route() error: %v", err)
		}
		if decision.ProviderName != "openai" {
			t.Errorf("ProviderName = %q, want openai", decision.ProviderName)
		}
	})

	t.Run("X-ZC-Upstream overrides default URL", func(t *testing.T) {
		c := NewZeptoClawConnector("", "", nil)
		body := `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer sk-key")
		req.Header.Set("X-ZC-Upstream", "https://custom-proxy.example.com/v1")

		decision, err := c.Route(req, []byte(body))
		if err != nil {
			t.Fatalf("Route() error: %v", err)
		}
		if !strings.HasPrefix(decision.UpstreamURL, "https://custom-proxy.example.com/v1") {
			t.Errorf("UpstreamURL = %q, want custom-proxy prefix", decision.UpstreamURL)
		}
	})

	t.Run("config providers override defaults", func(t *testing.T) {
		customProviders := map[string]ZCProviderEntry{
			"openai": {
				UpstreamURL: "https://my-private-openai.example.com/v1",
				AuthHeader:  "Authorization",
				AuthScheme:  "Bearer",
			},
		}
		c := NewZeptoClawConnector("", "", customProviders)
		body := `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer sk-key")

		decision, err := c.Route(req, []byte(body))
		if err != nil {
			t.Fatalf("Route() error: %v", err)
		}
		if !strings.Contains(decision.UpstreamURL, "my-private-openai.example.com") {
			t.Errorf("UpstreamURL = %q, want custom URL", decision.UpstreamURL)
		}
	})

	t.Run("Anthropic auth header resolution", func(t *testing.T) {
		c := NewZeptoClawConnector("", "", nil)
		body := `{"model":"claude-sonnet-4-20250514","messages":[{"role":"user","content":"hi"}]}`
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
		req.Header.Set("x-api-key", "sk-ant-key")

		decision, err := c.Route(req, []byte(body))
		if err != nil {
			t.Fatalf("Route() error: %v", err)
		}
		if decision.ProviderName != "anthropic" {
			t.Errorf("ProviderName = %q, want anthropic", decision.ProviderName)
		}
		if decision.AuthHeader != "x-api-key" {
			t.Errorf("AuthHeader = %q, want x-api-key", decision.AuthHeader)
		}
		if decision.AuthScheme != "" {
			t.Errorf("AuthScheme = %q, want empty", decision.AuthScheme)
		}
	})

	t.Run("provider/model format", func(t *testing.T) {
		c := NewZeptoClawConnector("", "", nil)
		body := `{"model":"anthropic/claude-sonnet-4-20250514","messages":[{"role":"user","content":"hi"}]}`
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer sk-key")

		decision, err := c.Route(req, []byte(body))
		if err != nil {
			t.Fatalf("Route() error: %v", err)
		}
		if decision.ProviderName != "anthropic" {
			t.Errorf("ProviderName = %q, want anthropic", decision.ProviderName)
		}
	})

	t.Run("unknown model without header errors", func(t *testing.T) {
		c := NewZeptoClawConnector("", "", nil)
		body := `{"model":"totally-unknown-model","messages":[{"role":"user","content":"hi"}]}`
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer sk-key")

		_, err := c.Route(req, []byte(body))
		if err == nil {
			t.Fatal("expected error for unknown model")
		}
		if !strings.Contains(err.Error(), "cannot determine provider") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("unknown provider errors", func(t *testing.T) {
		c := NewZeptoClawConnector("", "", nil)
		body := `{"model":"totally-unknown-model","messages":[{"role":"user","content":"hi"}]}`
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer sk-key")
		req.Header.Set("X-ZC-Provider", "nonexistent-provider")

		_, err := c.Route(req, []byte(body))
		if err == nil {
			t.Fatal("expected error for unknown provider")
		}
		if !strings.Contains(err.Error(), "unknown provider") {
			t.Errorf("unexpected error: %v", err)
		}
	})
}
