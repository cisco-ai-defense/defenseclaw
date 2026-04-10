package connector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGenericDetect(t *testing.T) {
	c := NewGenericConnector(nil)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	if !c.Detect(req) {
		t.Error("Generic connector should always detect")
	}
}

func TestGenericAuthenticate(t *testing.T) {
	c := NewGenericConnector(nil)

	tests := []struct {
		name       string
		remoteAddr string
		want       bool
	}{
		{"loopback", "127.0.0.1:1234", true},
		{"non-loopback", "192.168.1.1:1234", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
			req.RemoteAddr = tt.remoteAddr
			if got := c.Authenticate(req); got != tt.want {
				t.Errorf("Authenticate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGenericRoute(t *testing.T) {
	c := NewGenericConnector(nil)

	t.Run("infer openai from model", func(t *testing.T) {
		body := `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer sk-key")

		decision, err := c.Route(req, []byte(body))
		if err != nil {
			t.Fatalf("Route() error: %v", err)
		}
		if decision.ProviderName != "openai" {
			t.Errorf("ProviderName = %q, want openai", decision.ProviderName)
		}
		if decision.ConnectorName != "generic" {
			t.Errorf("ConnectorName = %q, want generic", decision.ConnectorName)
		}
	})

	t.Run("unknown model errors", func(t *testing.T) {
		body := `{"model":"unknown-thing","messages":[{"role":"user","content":"hi"}]}`
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer sk-key")

		_, err := c.Route(req, []byte(body))
		if err == nil {
			t.Fatal("expected error for unknown model")
		}
	})
}
