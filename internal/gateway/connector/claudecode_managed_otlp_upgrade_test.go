// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Upgrade removes the old managed native exporter and revokes its scoped
// bearer. Agent telemetry stays on the hook channel, while an unrelated
// operator env entry survives the settings transform.
func TestClaudeCodeManagedUpgradeRevokesUnverifiedNativeOTLP(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		t.Run(goos, func(t *testing.T) {
			dir := t.TempDir()
			settingsPath := filepath.Join(dir, "settings.json")
			if err := os.WriteFile(settingsPath, []byte(`{"env":{"OPERATOR_SETTING":"keep"}}`), 0o600); err != nil {
				t.Fatal(err)
			}
			previous := ClaudeCodeSettingsPathOverride
			ClaudeCodeSettingsPathOverride = settingsPath
			t.Cleanup(func() { ClaudeCodeSettingsPathOverride = previous })

			connector := NewClaudeCodeConnector()
			opts := SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:19081", APIToken: "test-hook-token", GOOS: goos, ManagedEnterprise: true}
			earlier := opts
			earlier.sandboxNativeOTLP = true // reproduce the earlier managed exporter
			if err := connector.Setup(context.Background(), earlier); err != nil {
				t.Fatalf("earlier setup: %v", err)
			}
			oldToken, err := LoadOTLPPathToken(dir, OTLPScopeClaude)
			if err != nil || oldToken == "" {
				t.Fatalf("earlier scoped token: present=%t err=%v", oldToken != "", err)
			}
			if err := connector.Setup(context.Background(), opts); err != nil {
				t.Fatalf("upgrade setup: %v", err)
			}
			data, err := os.ReadFile(settingsPath)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), oldToken) {
				t.Fatal("old native OTLP bearer remains in Claude settings")
			}
			var settings struct {
				Env map[string]string `json:"env"`
			}
			if err := json.Unmarshal(data, &settings); err != nil {
				t.Fatal(err)
			}
			if settings.Env["OPERATOR_SETTING"] != "keep" || settings.Env["CLAUDE_CODE_ENABLE_TELEMETRY"] != "0" ||
				settings.Env["OTEL_LOGS_EXPORTER"] != "none" || settings.Env["OTEL_METRICS_EXPORTER"] != "none" {
				t.Fatal("upgrade lost operator settings or left native telemetry enabled")
			}
			for key := range settings.Env {
				if strings.HasPrefix(key, "OTEL_EXPORTER_OTLP_") {
					t.Fatalf("old native OTLP setting %q remains", key)
				}
			}
			if token, err := LoadOTLPPathToken(dir, OTLPScopeClaude); err != nil || token != "" {
				t.Fatalf("old native OTLP token remains: present=%t err=%v", token != "", err)
			}
		})
	}
}
