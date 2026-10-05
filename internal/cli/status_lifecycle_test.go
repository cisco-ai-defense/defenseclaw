// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
)

func TestStatusLoadsStrictConfigWithoutOpeningAuditStore(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.Chmod(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEFENSECLAW_HOME", dataDir)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/health":
			if err := json.NewEncoder(w).Encode(gateway.HealthSnapshot{}); err != nil {
				t.Errorf("encode health: %v", err)
			}
		case "/status":
			if err := json.NewEncoder(w).Encode(map[string]any{}); err != nil {
				t.Errorf("encode status: %v", err)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	// The test server stands in for this home's gateway.
	previousManagedState := gatewayManagedState
	gatewayManagedState = func() (bool, int) { return true, os.Getpid() }
	t.Cleanup(func() { gatewayManagedState = previousManagedState })
	port := server.Listener.Addr().(*net.TCPAddr).Port
	configPath := filepath.Join(dataDir, "config.yaml")
	raw := "config_version: 8\ndata_dir: " + dataDir + "\ngateway:\n  api_port: " + strconv.Itoa(port) + "\nobservability: {}\n"
	if err := os.WriteFile(configPath, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}

	previousConfig, previousStore, previousLog, previousStartup := cfg, auditStore, auditLog, activeObservabilityV8Startup
	cfg, auditStore, auditLog, activeObservabilityV8Startup = nil, nil, nil, nil
	t.Cleanup(func() {
		cfg, auditStore, auditLog, activeObservabilityV8Startup =
			previousConfig, previousStore, previousLog, previousStartup
	})

	rootCmd.SetArgs([]string{"status"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })
	if _, err := rootCmd.ExecuteC(); err != nil {
		t.Fatal(err)
	}

	if cfg == nil || cfg.Gateway.APIPort != port {
		t.Fatalf("status config = %#v, want strict config-only load", cfg)
	}
	if auditStore != nil || auditLog != nil {
		t.Fatal("status opened the daemon audit store")
	}
	if _, err := os.Stat(filepath.Join(dataDir, "audit.db")); !os.IsNotExist(err) {
		t.Fatalf("status created audit.db: %v", err)
	}
}

// A gateway that exited on an error (for example a refused plugin folder)
// leaves that error as the last log line; status shows it.
func TestLastGatewayExitErrorReadsFinalLogLine(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", dataDir)
	logPath := filepath.Join(dataDir, "gateway.log")
	c := config.DefaultConfig()
	if err := os.WriteFile(logPath, []byte("[gateway] starting\nError: /home/u/.config/opencode/plugins can be written by other accounts\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, want := lastGatewayExitError(c), "/home/u/.config/opencode/plugins can be written by other accounts"; got != want {
		t.Fatalf("last exit = %q, want %q", got, want)
	}
	if err := os.WriteFile(logPath, []byte("Error: old failure\n[gateway] shutdown complete\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := lastGatewayExitError(c); got != "" {
		t.Fatalf("clean stop reported an exit error: %q", got)
	}
}
