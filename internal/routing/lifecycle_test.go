package routing

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLifecycle_NewDefaults(t *testing.T) {
	lc := NewLifecycle(LifecycleConfig{
		BinaryPath: "/usr/bin/sr",
		ConfigPath: "/etc/sr/config.yaml",
		DataDir:    "/tmp/sr",
		// Port not specified
	})

	if lc.port != 8080 {
		t.Errorf("expected default port 8080, got %d", lc.port)
	}
	if lc.binPath != "/usr/bin/sr" {
		t.Errorf("expected binPath /usr/bin/sr, got %s", lc.binPath)
	}
	if lc.configPath != "/etc/sr/config.yaml" {
		t.Errorf("expected configPath /etc/sr/config.yaml, got %s", lc.configPath)
	}
	if lc.dataDir != "/tmp/sr" {
		t.Errorf("expected dataDir /tmp/sr, got %s", lc.dataDir)
	}
}

func TestLifecycle_IsRunning_NilCmd(t *testing.T) {
	lc := NewLifecycle(LifecycleConfig{
		BinaryPath: "/usr/bin/sr",
		ConfigPath: "/etc/sr/config.yaml",
		Port:       9090,
		DataDir:    "/tmp/sr",
	})

	if lc.IsRunning() {
		t.Error("expected IsRunning to return false when cmd is nil")
	}
}

func TestLifecycle_Stop_NilProcess(t *testing.T) {
	lc := NewLifecycle(LifecycleConfig{
		BinaryPath: "/usr/bin/sr",
		ConfigPath: "/etc/sr/config.yaml",
		Port:       9090,
		DataDir:    "/tmp/sr",
	})

	// Should not panic
	err := lc.Stop()
	if err != nil {
		t.Errorf("expected Stop to return nil, got %v", err)
	}
}

func TestLifecycle_PID_NotStarted(t *testing.T) {
	lc := NewLifecycle(LifecycleConfig{
		BinaryPath: "/usr/bin/sr",
		ConfigPath: "/etc/sr/config.yaml",
		Port:       9090,
		DataDir:    "/tmp/sr",
	})

	if lc.PID() != 0 {
		t.Errorf("expected PID to return 0 when not started, got %d", lc.PID())
	}
}

func TestLifecycle_Port(t *testing.T) {
	lc := NewLifecycle(LifecycleConfig{
		BinaryPath: "/usr/bin/sr",
		ConfigPath: "/etc/sr/config.yaml",
		Port:       9191,
		DataDir:    "/tmp/sr",
	})

	if lc.Port() != 9191 {
		t.Errorf("expected Port to return 9191, got %d", lc.Port())
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
	// server.URL format: "http://127.0.0.1:PORT"
	// Parse to get port
	serverURL := server.URL
	var port int
	if _, err := fmt.Sscanf(serverURL, "http://127.0.0.1:%d", &port); err != nil {
		t.Fatalf("failed to parse server port: %v", err)
	}

	lc := NewLifecycle(LifecycleConfig{
		BinaryPath: "/usr/bin/sr",
		ConfigPath: "/etc/sr/config.yaml",
		Port:       port, // Use the httptest server port
		DataDir:    "/tmp/sr",
	})

	ctx := context.Background()
	err := lc.WaitForHealth(ctx, 2*time.Second)
	if err != nil {
		t.Errorf("expected WaitForHealth to succeed, got error: %v", err)
	}
}

func TestLifecycle_WaitForHealth_Timeout(t *testing.T) {
	// Use a port that has no server running
	lc := NewLifecycle(LifecycleConfig{
		BinaryPath: "/usr/bin/sr",
		ConfigPath: "/etc/sr/config.yaml",
		Port:       54321, // Random port with no server
		DataDir:    "/tmp/sr",
	})

	ctx := context.Background()
	err := lc.WaitForHealth(ctx, 500*time.Millisecond) // Short timeout
	if err == nil {
		t.Error("expected WaitForHealth to timeout, got nil error")
	}

	expectedErrMsg := "routing: sr health check timed out after"
	if err != nil && len(err.Error()) > 0 {
		if !contains(err.Error(), expectedErrMsg) {
			t.Errorf("expected error message to contain '%s', got: %v", expectedErrMsg, err)
		}
	}
}

func TestLifecycle_WaitForHealth_ContextCanceled(t *testing.T) {
	lc := NewLifecycle(LifecycleConfig{
		BinaryPath: "/usr/bin/sr",
		ConfigPath: "/etc/sr/config.yaml",
		Port:       54322, // Random port with no server
		DataDir:    "/tmp/sr",
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

func TestLifecycle_DataDir_CreatedOnStart(t *testing.T) {
	// Test that Start creates the data directory
	tmpDir := t.TempDir()
	dataDir := filepath.Join(tmpDir, "sr-data")

	// Create a mock binary that exits immediately (use /bin/true or similar)
	lc := NewLifecycle(LifecycleConfig{
		BinaryPath: "/bin/true", // Unix command that exits successfully
		ConfigPath: filepath.Join(tmpDir, "config.yaml"),
		Port:       9999,
		DataDir:    dataDir,
	})

	ctx := context.Background()
	err := lc.Start(ctx)

	// The binary will exit immediately, but dataDir should be created
	if err != nil {
		t.Logf("Start returned error (expected for /bin/true): %v", err)
	}

	// Check if dataDir was created
	if _, err := os.Stat(dataDir); os.IsNotExist(err) {
		t.Errorf("expected dataDir %s to be created, but it doesn't exist", dataDir)
	}

	// Cleanup
	lc.Stop()
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
