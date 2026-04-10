package connector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOpenClawDetect(t *testing.T) {
	c := NewOpenClawConnector("", "")

	tests := []struct {
		name   string
		header string
		want   bool
	}{
		{"with X-DC-Target-URL", "https://api.openai.com/v1/chat/completions", true},
		{"without header", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
			if tt.header != "" {
				req.Header.Set("X-DC-Target-URL", tt.header)
			}
			if got := c.Detect(req); got != tt.want {
				t.Errorf("Detect() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOpenClawAuthenticate(t *testing.T) {
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
			gatewayToken: "gw-token-123",
			headers:      map[string]string{"X-DC-Auth": "Bearer gw-token-123"},
			remoteAddr:   "192.168.1.1:1234",
			want:         true,
		},
		{
			name:         "invalid X-DC-Auth token",
			gatewayToken: "gw-token-123",
			headers:      map[string]string{"X-DC-Auth": "Bearer wrong-token"},
			remoteAddr:   "192.168.1.1:1234",
			want:         false,
		},
		{
			name:       "valid master key",
			masterKey:  "sk-dc-master123",
			headers:    map[string]string{"Authorization": "Bearer sk-dc-master123"},
			remoteAddr: "192.168.1.1:1234",
			want:       true,
		},
		{
			name:       "loopback without gateway token",
			remoteAddr: "127.0.0.1:1234",
			want:       true,
		},
		{
			name:         "loopback with gateway token requires auth",
			gatewayToken: "gw-token-123",
			remoteAddr:   "127.0.0.1:1234",
			want:         false,
		},
		{
			name:       "no auth configured (open proxy)",
			remoteAddr: "192.168.1.1:1234",
			want:       true,
		},
		{
			name:         "non-loopback without token",
			gatewayToken: "gw-token-123",
			remoteAddr:   "192.168.1.1:1234",
			want:         false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewOpenClawConnector(tt.gatewayToken, tt.masterKey)
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

func TestOpenClawRoute(t *testing.T) {
	c := NewOpenClawConnector("", "")

	t.Run("chat completions path", func(t *testing.T) {
		body := `{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}],"stream":true}`
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
		req.Header.Set("X-DC-Target-URL", "https://api.openai.com/v1/chat/completions")
		req.Header.Set("X-AI-Auth", "Bearer sk-test-key")

		decision, err := c.Route(req, []byte(body))
		if err != nil {
			t.Fatalf("Route() error: %v", err)
		}

		if decision.UpstreamURL != "https://api.openai.com/v1/chat/completions" {
			t.Errorf("UpstreamURL = %q", decision.UpstreamURL)
		}
		if decision.ProviderName != "openai" {
			t.Errorf("ProviderName = %q, want openai", decision.ProviderName)
		}
		if decision.APIKey != "sk-test-key" {
			t.Errorf("APIKey = %q", decision.APIKey)
		}
		if decision.AuthHeader != "Authorization" {
			t.Errorf("AuthHeader = %q, want Authorization", decision.AuthHeader)
		}
		if decision.AuthScheme != "Bearer" {
			t.Errorf("AuthScheme = %q, want Bearer", decision.AuthScheme)
		}
		if decision.Model != "gpt-4o" {
			t.Errorf("Model = %q, want gpt-4o", decision.Model)
		}
		if !decision.Stream {
			t.Error("Stream should be true")
		}
		if decision.PassthroughMode {
			t.Error("PassthroughMode should be false for chat completions")
		}
		if decision.ConnectorName != "openclaw" {
			t.Errorf("ConnectorName = %q, want openclaw", decision.ConnectorName)
		}
	})

	t.Run("passthrough path (Anthropic)", func(t *testing.T) {
		body := `{"model":"claude-sonnet-4-20250514","messages":[{"role":"user","content":"hi"}]}`
		req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(body))
		req.Header.Set("X-DC-Target-URL", "https://api.anthropic.com/v1/messages")
		req.Header.Set("X-AI-Auth", "Bearer sk-ant-key")
		req.Header.Set("anthropic-version", "2023-06-01")

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
		if !decision.PassthroughMode {
			t.Error("PassthroughMode should be true for /v1/messages")
		}
		if decision.ExtraUpstreamHeaders["anthropic-version"] != "2023-06-01" {
			t.Errorf("missing anthropic-version header")
		}
	})

	t.Run("Azure route", func(t *testing.T) {
		body := `{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}`
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
		req.Header.Set("X-DC-Target-URL", "https://myresource.openai.azure.com/openai/deployments/gpt-4/chat/completions?api-version=2024-02-01")
		req.Header.Set("X-AI-Auth", "Bearer az-key-123")

		decision, err := c.Route(req, []byte(body))
		if err != nil {
			t.Fatalf("Route() error: %v", err)
		}

		if decision.ProviderName != "azure" {
			t.Errorf("ProviderName = %q, want azure", decision.ProviderName)
		}
		if decision.AuthHeader != "api-key" {
			t.Errorf("AuthHeader = %q, want api-key", decision.AuthHeader)
		}
	})

	t.Run("missing X-DC-Target-URL", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
		_, err := c.Route(req, []byte(`{}`))
		if err == nil {
			t.Fatal("expected error for missing X-DC-Target-URL")
		}
	})

	t.Run("SSRF blocked", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
		req.Header.Set("X-DC-Target-URL", "http://169.254.169.254/latest/meta-data")
		_, err := c.Route(req, []byte(`{}`))
		if err == nil {
			t.Fatal("expected error for SSRF attempt")
		}
		if !strings.Contains(err.Error(), "known LLM provider domain") {
			t.Errorf("unexpected error: %v", err)
		}
	})
}
