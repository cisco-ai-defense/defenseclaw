// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-1609: gateway status --json prints one JSON document, also when the
// gateway is not running.
func TestGatewayStatusJSONWhenNotRunning(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	previousConfig, previousState, previousJSON := cfg, gatewayManagedState, gatewayStatusJSON
	t.Cleanup(func() { cfg, gatewayManagedState, gatewayStatusJSON = previousConfig, previousState, previousJSON })
	cfg = &config.Config{DataDir: t.TempDir()}
	cfg.Gateway.APIBind = "127.0.0.1"
	cfg.Gateway.APIPort = port
	gatewayManagedState = func() (bool, int) { return false, 0 }
	gatewayStatusJSON = true

	var runErr error
	out := captureStdout(t, func() { runErr = runSidecarStatus(nil, nil) })
	if runErr == nil {
		t.Fatalf("status --json of a stopped gateway succeeded:\n%s", out)
	}
	var doc gatewayStatusDocument
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("status --json is not JSON (%v):\n%s", err, out)
	}
	if doc.Running || doc.Health != nil || !strings.Contains(doc.Hint, "defenseclaw-gateway start") ||
		!strings.Contains(doc.Endpoint, fmt.Sprint(port)) {
		t.Fatalf("status --json document = %+v", doc)
	}
	if statusCmd.Flags().Lookup("json") == nil {
		t.Fatal("gateway status has no --json flag")
	}
}

// GAP-1353: a missing destination secret names the keys set step, as start
// and restart do.
func TestGatewayStatusConfigLoadErrorNamesKeysSet(t *testing.T) {
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	err := gatewayStatusConfigLoadError(fmt.Errorf("failed to load config: %w", &config.V8SecretReferenceError{
		Destination: "galileo",
		Path:        `observability.destinations[0].headers["Galileo-API-Key"]`,
		Reference:   "GALILEO_API_KEY",
	}))
	if err == nil || !strings.Contains(err.Error(), "defenseclaw keys set GALILEO_API_KEY") ||
		!strings.Contains(err.Error(), "The gateway is not running") {
		t.Fatalf("status refusal = %v", err)
	}
}

// GAP-1622: a runnable group shows its subcommand form in the usage line.
func TestUsageErrorShowsSubcommandFormOfRunnableGroup(t *testing.T) {
	group := &cobra.Command{Use: "watchdog", RunE: func(*cobra.Command, []string) error { return nil }}
	group.AddCommand(&cobra.Command{Use: "status", RunE: func(*cobra.Command, []string) error { return nil }})
	err := unexpectedArgs(group, []string{"bogus"})
	if err == nil || !strings.Contains(err.Error(), "watchdog [command]") || !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("usage error = %v", err)
	}
}
