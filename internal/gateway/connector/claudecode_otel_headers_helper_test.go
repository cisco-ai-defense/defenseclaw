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

func TestClaudeCodeUpgradeRemovesNativeExporterAndLegacyHelper(t *testing.T) {
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "claude-settings", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o755); err != nil {
		t.Fatal(err)
	}
	ClaudeCodeSettingsPathOverride = settingsPath
	defer func() { ClaudeCodeSettingsPathOverride = "" }()

	c := NewClaudeCodeConnector()
	opts := SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:18970"}
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	read := func() map[string]interface{} {
		t.Helper()
		data, err := os.ReadFile(settingsPath)
		if err != nil {
			t.Fatal(err)
		}
		var settings map[string]interface{}
		if err := json.Unmarshal(data, &settings); err != nil {
			t.Fatal(err)
		}
		return settings
	}

	// Simulate the earlier 1.0.4 train's helper setup and a live process that would have sent
	// its native OTLP stream to whoever later bound the gateway API port.
	legacyHelper := filepath.Join(dir, "hooks", claudeCodeOTLPHeadersHelperScript)
	settings := read()
	settings[claudeCodeOTLPHeadersHelperKey] = legacyHelper
	settings["env"] = map[string]interface{}{
		"CLAUDE_CODE_ENABLE_TELEMETRY": "1",
		"OTEL_EXPORTER_OTLP_ENDPOINT":  "http://127.0.0.1:18970",
		"OTEL_EXPORTER_OTLP_HEADERS":   "x-defenseclaw-client=claudecode-otel/1.0",
		"OTEL_LOGS_EXPORTER":           "otlp",
		"OTEL_METRICS_EXPORTER":        "otlp",
	}
	data, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settingsPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	backup, err := c.loadBackup(dir)
	if err != nil {
		t.Fatal(err)
	}
	backup.ManagedOTLPHeadersHelper = legacyHelper
	backup.ManagedEnv = map[string]string{}
	for key, value := range settings["env"].(map[string]interface{}) {
		backup.ManagedEnv[key] = value.(string)
	}
	if err := c.saveBackup(dir, backup); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hooks", ".otlp-claudecode.token"), []byte(strings.Repeat("a", 64)), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("upgrade setup: %v", err)
	}
	settings = read()
	if _, present := settings[claudeCodeOTLPHeadersHelperKey]; present {
		t.Fatalf("legacy helper remains in settings: %v", settings[claudeCodeOTLPHeadersHelperKey])
	}
	env := settings["env"].(map[string]interface{})
	for _, key := range []string{"OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_HEADERS"} {
		if _, present := env[key]; present {
			t.Fatalf("legacy native exporter setting %s remains: %v", key, env[key])
		}
	}
	for _, key := range []string{"OTEL_LOGS_EXPORTER", "OTEL_METRICS_EXPORTER", "OTEL_TRACES_EXPORTER"} {
		if env[key] != "none" {
			t.Fatalf("%s = %v, want none", key, env[key])
		}
	}
	if env["CLAUDE_CODE_ENABLE_TELEMETRY"] != "0" {
		t.Fatalf("per-user telemetry is unsafe: %v", env)
	}
	// No 1.0.4 render reads a fail mode from Claude's env; a per-user setup
	// writes none (TestClaudeCodePerUserSetupTakesBackTheFailModeCarrier).
	if _, present := env["DEFENSECLAW_FAIL_MODE"]; present {
		t.Fatalf("per-user setup wrote a fail-mode carrier: %v", env)
	}
	if _, err := os.Stat(filepath.Join(dir, "hooks", ".otlp-claudecode.token")); !os.IsNotExist(err) {
		t.Fatalf("legacy token remains after upgrade: %v", err)
	}
}

// Released 0.8.10 and 1.0.0-1.0.3 per-user setups used a static native
// bearer, not the later 1.0.4 train's helper. Exercise that released shape
// with each host OS option so the upgrade revokes it everywhere.
func TestClaudeCodeReleasedStaticNativeExporterUpgradeAcrossOS(t *testing.T) {
	for _, released := range []struct {
		name, promptCapture string
	}{
		{name: "0.8.10", promptCapture: "1"},
		{name: "1.0.0-1.0.3", promptCapture: "0"},
	} {
		for _, goos := range []string{"linux", "darwin", "windows"} {
			t.Run(released.name+"/"+goos, func(t *testing.T) {
				dir := t.TempDir()
				settingsPath := filepath.Join(dir, "settings.json")
				previous := ClaudeCodeSettingsPathOverride
				ClaudeCodeSettingsPathOverride = settingsPath
				t.Cleanup(func() { ClaudeCodeSettingsPathOverride = previous })

				c := NewClaudeCodeConnector()
				opts := SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:18970", GOOS: goos}
				if err := c.Setup(context.Background(), opts); err != nil {
					t.Fatal(err)
				}
				legacy := opts
				legacy.ManagedEnterprise = true
				legacy.OTLPPathToken = strings.Repeat("b", 64)
				oldEnv := buildClaudeCodeOtelEnv(legacy)
				oldEnv["DEFENSECLAW_FAIL_MODE"] = "open"
				oldEnv["OTEL_LOG_USER_PROMPTS"] = released.promptCapture
				if released.name == "0.8.10" {
					for _, key := range []string{"OTEL_LOG_ASSISTANT_RESPONSES", "OTEL_LOG_TOOL_DETAILS", "OTEL_LOG_TOOL_CONTENT", "OTEL_LOG_RAW_API_BODIES"} {
						delete(oldEnv, key)
					}
				}
				data, err := os.ReadFile(settingsPath)
				if err != nil {
					t.Fatal(err)
				}
				var settings map[string]interface{}
				if err := json.Unmarshal(data, &settings); err != nil {
					t.Fatal(err)
				}
				settings["env"] = oldEnv
				data, err = json.Marshal(settings)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(settingsPath, data, 0o600); err != nil {
					t.Fatal(err)
				}
				backup, err := c.loadBackup(dir)
				if err != nil {
					t.Fatal(err)
				}
				backup.ManagedEnv = oldEnv
				if err := c.saveBackup(dir, backup); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "hooks", ".otlp-claudecode.token"), []byte(legacy.OTLPPathToken), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := c.Setup(context.Background(), opts); err != nil {
					t.Fatalf("upgrade setup: %v", err)
				}
				data, err = os.ReadFile(settingsPath)
				if err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(data, &settings); err != nil {
					t.Fatal(err)
				}
				env := settings["env"].(map[string]interface{})
				if env["CLAUDE_CODE_ENABLE_TELEMETRY"] != "0" || env["OTEL_LOGS_EXPORTER"] != "none" ||
					env["OTEL_METRICS_EXPORTER"] != "none" {
					t.Fatalf("native telemetry stayed enabled: %v", env)
				}
				if strings.Contains(string(data), legacy.OTLPPathToken) || strings.Contains(string(data), "http://127.0.0.1:18970") {
					t.Fatalf("released static native endpoint or credential remains: %s", data)
				}
				if token, err := LoadOTLPPathToken(dir, OTLPScopeClaude); err != nil || token != "" {
					t.Fatalf("released native token remains: present=%t err=%v", token != "", err)
				}
			})
		}
	}
}
