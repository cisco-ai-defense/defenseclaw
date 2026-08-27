package routing

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestLifecycle_NewDefaults(t *testing.T) {
	lc := NewLifecycle(LifecycleConfig{
		ConfigPath: "/etc/sr/config.yaml",
		// Port not specified
	})

	if lc.port != DefaultAPIPort {
		t.Errorf("expected default port %d, got %d", DefaultAPIPort, lc.port)
	}
	if lc.configPath != "/etc/sr/config.yaml" {
		t.Errorf("expected configPath /etc/sr/config.yaml, got %s", lc.configPath)
	}
}

func TestLifecycle_DockerRunArgsAreLoopbackReadOnlyAndVersioned(t *testing.T) {
	lc := NewLifecycle(LifecycleConfig{
		ConfigPath: "/var/lib/defenseclaw/semantic-router/config.yaml",
		Port:       9191,
		DataDir:    "/var/lib/defenseclaw/semantic-router",
		Version:    TestedVersion,
	})
	args, err := lc.dockerRunArgs()
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"127.0.0.1:9191:8080",
		"/var/lib/defenseclaw/semantic-router:/app/config:ro",
		"ghcr.io/vllm-project/semantic-router/vllm-sr:v" + TestedVersion,
		testedImageDigest,
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges:true",
		"--read-only",
		"/tmp:rw,noexec,nosuid,size=64m",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("docker args %q missing %q", joined, want)
		}
	}
	if !slices.Contains(args, "--pull=missing") {
		t.Fatalf("docker args %q missing --pull=missing", joined)
	}
	if slices.Contains(args, "--entrypoint") {
		t.Fatalf("docker args %q should use the versioned image entrypoint", joined)
	}
}

func TestLifecycle_RejectsUnsafeVersionBeforeDocker(t *testing.T) {
	lc := NewLifecycle(LifecycleConfig{Version: "0.3.0;latest"})
	if _, err := lc.dockerRunArgs(); err == nil || !strings.Contains(err.Error(), "invalid semantic-router version") {
		t.Fatalf("dockerRunArgs error = %v, want invalid version", err)
	}
}

func TestLifecycle_RejectsUntestedVersionBeforeDocker(t *testing.T) {
	lc := NewLifecycle(LifecycleConfig{Version: "0.4.0"})
	if _, err := lc.dockerRunArgs(); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("dockerRunArgs error = %v, want unsupported version", err)
	}
}

func TestLifecycle_ContainerNameDoesNotExposeDataDirectory(t *testing.T) {
	lc := NewLifecycle(LifecycleConfig{DataDir: "/Users/alice/private/semantic-router"})
	if strings.Contains(lc.containerName, "alice") || !strings.HasPrefix(lc.containerName, "defenseclaw-sr-") {
		t.Fatalf("containerName = %q", lc.containerName)
	}
}

func TestLifecycle_NewWithPort(t *testing.T) {
	lc := NewLifecycle(LifecycleConfig{
		ConfigPath: "/etc/sr/config.yaml",
		Port:       9090,
	})

	if lc.port != 9090 {
		t.Errorf("expected port 9090, got %d", lc.port)
	}
}

func TestLifecycle_Port(t *testing.T) {
	lc := NewLifecycle(LifecycleConfig{
		ConfigPath: "/etc/sr/config.yaml",
		Port:       9191,
	})

	if lc.Port() != 9191 {
		t.Errorf("expected Port() to return 9191, got %d", lc.Port())
	}
}

func TestLifecycle_IsRunning_NoServer(t *testing.T) {
	lc := NewLifecycle(LifecycleConfig{
		ConfigPath: "/etc/sr/config.yaml",
		Port:       54321, // Random port with no server
	})

	if lc.IsRunning() {
		t.Error("expected IsRunning() to return false when no server is running")
	}
}

func TestLifecycle_WaitForHealth_Success(t *testing.T) {
	// Create a mock HTTP server that responds with 200 OK on /health
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok"}`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Extract port from server URL
	var port int
	if _, err := fmt.Sscanf(server.URL, "http://127.0.0.1:%d", &port); err != nil {
		t.Fatalf("failed to parse server port: %v", err)
	}

	lc := NewLifecycle(LifecycleConfig{
		ConfigPath: "/etc/sr/config.yaml",
		Port:       port,
	})

	ctx := context.Background()
	err := lc.WaitForHealth(ctx, 2*time.Second)
	if err != nil {
		t.Errorf("expected WaitForHealth to succeed, got error: %v", err)
	}
}

func TestLifecycle_WaitForHealth_Timeout(t *testing.T) {
	lc := NewLifecycle(LifecycleConfig{
		ConfigPath: "/etc/sr/config.yaml",
		Port:       54322, // Random port with no server
	})

	ctx := context.Background()
	err := lc.WaitForHealth(ctx, 500*time.Millisecond)
	if err == nil {
		t.Error("expected WaitForHealth to timeout, got nil error")
	}

	expectedErrMsg := "routing: router health check timed out"
	if err != nil && len(err.Error()) > 0 {
		if !contains(err.Error(), expectedErrMsg) {
			t.Errorf("expected error message to contain '%s', got: %v", expectedErrMsg, err)
		}
	}
}

func TestLifecycle_WaitForHealth_ContextCanceled(t *testing.T) {
	lc := NewLifecycle(LifecycleConfig{
		ConfigPath: "/etc/sr/config.yaml",
		Port:       54323,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := lc.WaitForHealth(ctx, 5*time.Second)
	if err == nil {
		t.Error("expected WaitForHealth to return context error, got nil")
	}
	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}

func TestLifecycle_Stop_NilCmd(t *testing.T) {
	lc := NewLifecycle(LifecycleConfig{
		ConfigPath: "/etc/sr/config.yaml",
		Port:       9999,
	})

	// Should not panic when cmd is nil
	err := lc.Stop()
	if err != nil {
		t.Errorf("expected Stop to return nil, got %v", err)
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
