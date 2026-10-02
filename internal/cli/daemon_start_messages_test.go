// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// GAP-1864: a gateway that exits before readiness reports the error it
// logged (here a locked audit database), not the health probe's refusal,
// and never an error an earlier run left in gateway.log.
func TestGatewayExitedBeforeReadinessNamesTheLoggedCause(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "gateway.log")
	if err := os.WriteFile(logPath, []byte("Error: an older run failed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	offset := gatewayLogSize(logPath)
	probe := fmt.Errorf("%w (last health probe: dial tcp: connection refused)", errGatewayExitedBeforeReadiness)
	if err := gatewayExitedBeforeReadinessError(probe, logPath, offset); err != probe {
		t.Fatalf("no new log error: %v, want the probe error", err)
	}
	file, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = file.WriteString("[gateway] starting\nError: failed to open audit store: audit: refresh baselines: database is locked (5) (SQLITE_BUSY)\n")
	_ = file.Close()
	msg := gatewayExitedBeforeReadinessError(probe, logPath, offset).Error()
	for _, want := range []string{"another program has the audit database locked", "database is locked (5)", "try again in a moment"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not contain %q", msg, want)
		}
	}
	if strings.Contains(msg, "connection refused") || strings.Contains(msg, "older run") {
		t.Errorf("error %q still shows the probe detail or an old error", msg)
	}
}

// GAP-1876: the gateway's empty-config message dates the kept copy, as the
// Python CLI does (GAP-1786).
func TestEmptyConfigMessageDatesThePreviousCopy(t *testing.T) {
	home := t.TempDir()
	kept := filepath.Join(home, "previous", "data", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(kept), 0o700); err != nil {
		t.Fatal(err)
	}
	for path, content := range map[string]string{kept: "config_version: 8\n", filepath.Join(home, "previous", "VERSION"): "0.8.10\n"} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	when := time.Date(2026, 10, 2, 4, 40, 0, 0, time.UTC)
	if err := os.Chtimes(kept, when, when); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(home, "config.yaml")
	if err := os.WriteFile(cfgPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	msg, empty := emptyConfigFileMessage(cfgPath)
	want := "the last version upgrade kept the DefenseClaw 0.8.10 config from 2026-10-02 04:40 UTC in " + kept +
		"; it lacks every change made since then"
	if !empty || !strings.Contains(msg, want) {
		t.Fatalf("message %q does not contain %q", msg, want)
	}
	if err := os.RemoveAll(filepath.Join(home, "previous")); err != nil {
		t.Fatal(err)
	}
	if msg, _ := emptyConfigFileMessage(cfgPath); strings.Contains(msg, "previous") ||
		!strings.Contains(msg, "Restore your copy of config.yaml, or remove the empty file") {
		t.Fatalf("message without a kept copy = %q", msg)
	}
}

func writeGatewayMessageConfig(t *testing.T, body string) string {
	t.Helper()
	home := t.TempDir()
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("DEFENSECLAW_HOME", home)
	t.Setenv("DEFENSECLAW_CONFIG", configPath)
	raw := fmt.Sprintf("config_version: 8\ndata_dir: %s\ngateway:\n  api_bind: 127.0.0.1\n  api_port: 19132\n%s",
		filepath.ToSlash(home), body)
	if err := os.WriteFile(configPath, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := cfg
	t.Cleanup(func() { cfg = previous; gatewayStatusConfigProblem = nil })
	return configPath
}

// GAP-1900: gateway status names a missing destination key with one remedy.
func TestGatewayStatusMissingDestinationKeyGivesOneRemedy(t *testing.T) {
	const secretEnv = "DC_TEST_STATUS_ONE_REMEDY_KEY"
	t.Setenv(secretEnv, "")
	configPath := writeGatewayMessageConfig(t, fmt.Sprintf(`observability:
  destinations:
    - name: galileo
      kind: otlp
      endpoint: https://collector.example.test
      headers:
        Galileo-API-Key: {env: %s}
`, secretEnv))
	loadErr := loadGatewayCommandConfigFor(statusCmd)
	if loadErr == nil {
		t.Fatal("config with a missing destination secret loaded")
	}
	msg := gatewayStatusConfigLoadError(loadErr).Error()
	if n := strings.Count(strings.ToLower(msg), "set it with"); n != 1 {
		t.Errorf("status error gives the remedy %d times: %q", n, msg)
	}
	for _, want := range []string{
		`observability destination "galileo" needs ` + secretEnv + ", which is not set",
		"defenseclaw keys set " + secretEnv, `remove destination "galileo" from ` + configPath,
		"then run: defenseclaw-gateway start",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("status error %q does not contain %q", msg, want)
		}
	}
	if strings.Contains(msg, "config_semantic_invalid") {
		t.Errorf("status error shows the internal code: %q", msg)
	}
}

// GAP-1914: restart and status name the bad enum value and the allowed
// values, as config validate does, not the raw schema diagnostic.
func TestGatewayConfigLoadErrorNamesTheBadEnumValue(t *testing.T) {
	configPath := writeGatewayMessageConfig(t, "guardrail:\n  mode: enforce-everything\n")
	loadErr := loadGatewayCommandConfigFor(statusCmd)
	if loadErr == nil {
		t.Fatal("config with an invalid guardrail.mode loaded")
	}
	for _, msg := range []string{
		daemonConfigLoadError("restart", loadErr).Error(),
		gatewayStatusConfigLoadError(loadErr).Error(),
	} {
		want := configPath + ` line 7: guardrail.mode is "enforce-everything"; allowed values: observe, action`
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not contain %q", msg, want)
		}
		for _, internal := range []string{"config_schema_invalid", "canonical v8 schema", "received string"} {
			if strings.Contains(msg, internal) {
				t.Errorf("error %q still shows %q", msg, internal)
			}
		}
	}
}
