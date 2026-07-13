package training

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLlamaServer_Defaults(t *testing.T) {
	cfg := LlamaConfig{
		ModelsDir: "/tmp/models",
	}

	server := NewLlamaServer(cfg)

	if server.Port() != 8090 {
		t.Errorf("expected default port 8090, got %d", server.Port())
	}

	if server.cfg.MaxModels != 4 {
		t.Errorf("expected default MaxModels 4, got %d", server.cfg.MaxModels)
	}

	if server.cfg.Binary != "llama-server" {
		t.Errorf("expected default binary 'llama-server', got %s", server.cfg.Binary)
	}
}

func TestLlamaServer_IsHealthy_MockServer(t *testing.T) {
	// Create mock HTTP server that returns 200 OK
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer mockServer.Close()

	// Extract port from mock server
	addr := mockServer.Listener.Addr().String()
	var port int
	if _, err := fmt.Sscanf(addr, "127.0.0.1:%d", &port); err != nil {
		t.Fatalf("failed to parse mock server port: %v", err)
	}

	cfg := LlamaConfig{
		ModelsDir: "/tmp/models",
		Port:      port,
	}

	server := NewLlamaServer(cfg)

	if !server.IsHealthy() {
		t.Error("expected IsHealthy() to return true for mock server")
	}
}

func TestLlamaServer_IsHealthy_NoServer(t *testing.T) {
	cfg := LlamaConfig{
		ModelsDir: "/tmp/models",
		Port:      19999, // unlikely to be in use
	}

	server := NewLlamaServer(cfg)

	if server.IsHealthy() {
		t.Error("expected IsHealthy() to return false when no server is running")
	}
}

func TestLlamaServer_Port(t *testing.T) {
	tests := []struct {
		name string
		port int
		want int
	}{
		{
			name: "explicit port",
			port: 9000,
			want: 9000,
		},
		{
			name: "default port",
			port: 0,
			want: 8090,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := LlamaConfig{
				ModelsDir: "/tmp/models",
				Port:      tt.port,
			}

			server := NewLlamaServer(cfg)

			if server.Port() != tt.want {
				t.Errorf("expected port %d, got %d", tt.want, server.Port())
			}
		})
	}
}
