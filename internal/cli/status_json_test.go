// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
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

// GAP-1788: with only a destination secret missing, gateway status still
// loads enough of config.yaml to query the gateway, then reports the
// problem with a fix that works (not "disable that destination").
func TestGatewayStatusMissingDestinationSecretStillFindsGateway(t *testing.T) {
	home := t.TempDir()
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	const secretEnv = "DC_TEST_STATUS_MISSING_KEY"
	t.Setenv("DEFENSECLAW_HOME", home)
	t.Setenv("DEFENSECLAW_CONFIG", configPath)
	t.Setenv(secretEnv, "")
	raw := fmt.Sprintf(`config_version: 8
data_dir: %s
gateway:
  api_bind: 127.0.0.1
  api_port: 19131
observability:
  destinations:
    - name: galileo
      kind: otlp
      endpoint: https://collector.example.test
      headers:
        Galileo-API-Key: {env: %s}
`, filepath.ToSlash(home), secretEnv)
	if err := os.WriteFile(configPath, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := cfg
	t.Cleanup(func() { cfg = previous; gatewayStatusConfigProblem = nil })

	loadErr := loadGatewayCommandConfigFor(statusCmd)
	if loadErr == nil {
		t.Fatal("config with a missing destination secret loaded")
	}
	relaxed := gatewayStatusRelaxedConfig(loadErr)
	if relaxed == nil || relaxed.Gateway.APIPort != 19131 {
		t.Fatalf("relaxed config = %+v (load error %v)", relaxed, loadErr)
	}
	msg := gatewayStatusConfigLoadError(loadErr).Error()
	for _, want := range []string{"defenseclaw keys set " + secretEnv, `remove destination "galileo" from ` + configPath} {
		if !strings.Contains(msg, want) {
			t.Errorf("status error %q does not contain %q", msg, want)
		}
	}
	if strings.Contains(msg, "disable that destination") {
		t.Errorf("status error still advises a disable that setup refuses: %q", msg)
	}
	if gatewayStatusRelaxedConfig(errors.New("failed to load config: bad yaml")) != nil {
		t.Error("a non-secret error was relaxed")
	}
}

// GAP-2062: an invalid enum value does not hide the running gateway either:
// status drops the value to find the gateway, then reports the problem.
func TestGatewayStatusInvalidEnumStillFindsGateway(t *testing.T) {
	home := t.TempDir()
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("DEFENSECLAW_HOME", home)
	t.Setenv("DEFENSECLAW_CONFIG", configPath)
	raw := fmt.Sprintf(`config_version: 8
data_dir: %s
gateway:
  api_bind: 127.0.0.1
  api_port: 19132
guardrail:
  mode: enforce-everything
`, filepath.ToSlash(home))
	if err := os.WriteFile(configPath, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := cfg
	t.Cleanup(func() { cfg = previous; gatewayStatusConfigProblem = nil })

	loadErr := loadGatewayCommandConfigFor(statusCmd)
	if loadErr == nil {
		t.Fatal("config with an invalid guardrail.mode loaded")
	}
	relaxed := gatewayStatusRelaxedConfig(loadErr)
	if relaxed == nil || relaxed.Gateway.APIPort != 19132 {
		t.Fatalf("relaxed config = %+v (load error %v)", relaxed, loadErr)
	}
	msg := gatewayStatusConfigLoadError(loadErr).Error()
	if !strings.Contains(msg, `guardrail.mode is "enforce-everything"`) {
		t.Errorf("status error %q does not name the invalid value", msg)
	}
}

// GAP-2118: a value of the wrong type (alone or next to an invalid enum)
// does not hide the running gateway either.
func TestGatewayStatusWrongTypeValueStillFindsGateway(t *testing.T) {
	for name, extra := range map[string]string{
		"list for string":   "  block_message: [1, 2]\n",
		"text for boolean":  "  enabled: maybe\n",
		"text for integer":  "  port: notaport\n",
		"enum plus boolean": "  mode: enforce-everything\n  enabled: maybe\n",
	} {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			configPath := filepath.Join(t.TempDir(), "config.yaml")
			t.Setenv("DEFENSECLAW_HOME", home)
			t.Setenv("DEFENSECLAW_CONFIG", configPath)
			raw := fmt.Sprintf("config_version: 8\ndata_dir: %s\ngateway:\n  api_bind: 127.0.0.1\n  api_port: 19133\nguardrail:\n%s",
				filepath.ToSlash(home), extra)
			if err := os.WriteFile(configPath, []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			previous := cfg
			t.Cleanup(func() { cfg = previous; gatewayStatusConfigProblem = nil })

			loadErr := loadGatewayCommandConfigFor(statusCmd)
			if loadErr == nil {
				t.Fatal("config with a wrong-type value loaded")
			}
			relaxed := gatewayStatusRelaxedConfig(loadErr)
			if relaxed == nil || relaxed.Gateway.APIPort != 19133 {
				t.Fatalf("relaxed config = %+v (load error %v)", relaxed, loadErr)
			}
		})
	}
}

func TestYAMLWithoutPath(t *testing.T) {
	out, ok := yamlWithoutPath([]byte("a:\n  b: 1\n  c: [x, y]\n"), "$.a.c[0]")
	if !ok || strings.Contains(string(out), "x") || !strings.Contains(string(out), "b: 1") {
		t.Fatalf("yamlWithoutPath = %q, %v", out, ok)
	}
	if _, ok := yamlWithoutPath([]byte("a: 1\n"), "$.missing"); ok {
		t.Error("a missing path was removed")
	}
}
