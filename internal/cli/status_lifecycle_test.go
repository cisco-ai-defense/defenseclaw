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
