package connector

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestInferProviderFromURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{"openai", "https://api.openai.com/v1/chat/completions", "openai"},
		{"anthropic", "https://api.anthropic.com/v1/messages", "anthropic"},
		{"empty for unknown", "https://evil.example.com/foo", ""},
		{"empty string", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := InferProviderFromURL(tt.url)
			if got != tt.want {
				t.Errorf("InferProviderFromURL(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}

func TestIsKnownProviderDomain(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{"openai", "https://api.openai.com/v1/chat/completions", true},
		{"anthropic", "https://api.anthropic.com/v1/messages", true},
		{"unknown domain", "https://evil.example.com/foo", false},
		{"SSRF bypass attempt", "https://evil.com/?foo=api.openai.com", false},
		{"empty", "", false},
		{"invalid url", "://bad", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsKnownProviderDomain(tt.url)
			if got != tt.want {
				t.Errorf("IsKnownProviderDomain(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestScrubURLSecrets(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string // check that sensitive params are REDACTED
	}{
		{"no query string", "https://api.openai.com/v1", "https://api.openai.com/v1"},
		{"key param", "https://api.example.com/v1?key=secret123", ""},
		{"no sensitive params", "https://api.example.com/v1?model=gpt4", "https://api.example.com/v1?model=gpt4"},
		{"invalid url", "://bad", "://bad"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ScrubURLSecrets(tt.raw)
			if tt.want != "" {
				if got != tt.want {
					t.Errorf("ScrubURLSecrets(%q) = %q, want %q", tt.raw, got, tt.want)
				}
			} else {
				// For "key param" case, just verify the secret is redacted
				if got == tt.raw {
					t.Errorf("ScrubURLSecrets(%q) should have redacted secrets but returned unchanged", tt.raw)
				}
			}
		})
	}
}

func TestExtractAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		headers    map[string]string
		wantKey    string
		wantHeader string
		wantScheme string
	}{
		{
			name:       "X-AI-Auth Bearer",
			headers:    map[string]string{"X-AI-Auth": "Bearer sk-test-key"},
			wantKey:    "sk-test-key",
			wantHeader: "Authorization",
			wantScheme: "Bearer",
		},
		{
			name:       "api-key (Azure)",
			headers:    map[string]string{"api-key": "azure-key-123"},
			wantKey:    "azure-key-123",
			wantHeader: "api-key",
			wantScheme: "",
		},
		{
			name:       "x-api-key (Anthropic)",
			headers:    map[string]string{"x-api-key": "sk-ant-key"},
			wantKey:    "sk-ant-key",
			wantHeader: "x-api-key",
			wantScheme: "",
		},
		{
			name:       "Authorization Bearer",
			headers:    map[string]string{"Authorization": "Bearer sk-real-key"},
			wantKey:    "sk-real-key",
			wantHeader: "Authorization",
			wantScheme: "Bearer",
		},
		{
			name:       "skip master key in X-AI-Auth",
			headers:    map[string]string{"X-AI-Auth": "Bearer sk-dc-masterkey", "Authorization": "Bearer sk-real"},
			wantKey:    "sk-real",
			wantHeader: "Authorization",
			wantScheme: "Bearer",
		},
		{
			name:       "skip master key in Authorization",
			headers:    map[string]string{"Authorization": "Bearer sk-dc-masterkey"},
			wantKey:    "",
			wantHeader: "",
			wantScheme: "",
		},
		{
			name:       "no auth headers",
			headers:    map[string]string{},
			wantKey:    "",
			wantHeader: "",
			wantScheme: "",
		},
		{
			name:       "priority: X-AI-Auth over Authorization",
			headers:    map[string]string{"X-AI-Auth": "Bearer sk-priority", "Authorization": "Bearer sk-other"},
			wantKey:    "sk-priority",
			wantHeader: "Authorization",
			wantScheme: "Bearer",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			key, hdr, scheme := ExtractAPIKey(req, "sk-dc-")
			if key != tt.wantKey {
				t.Errorf("key = %q, want %q", key, tt.wantKey)
			}
			if hdr != tt.wantHeader {
				t.Errorf("header = %q, want %q", hdr, tt.wantHeader)
			}
			if scheme != tt.wantScheme {
				t.Errorf("scheme = %q, want %q", scheme, tt.wantScheme)
			}
		})
	}
}

func TestIsLoopback(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		want       bool
	}{
		{"IPv4 loopback", "127.0.0.1:12345", true},
		{"IPv6 loopback", "[::1]:12345", true},
		{"non-loopback", "192.168.1.100:12345", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
			req.RemoteAddr = tt.remoteAddr
			if got := IsLoopback(req); got != tt.want {
				t.Errorf("IsLoopback(%q) = %v, want %v", tt.remoteAddr, got, tt.want)
			}
		})
	}
}
