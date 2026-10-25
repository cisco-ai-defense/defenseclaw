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

func writeClaudeUpgradeSettings(t *testing.T, path string, settings map[string]interface{}) {
	t.Helper()
	data, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	pinClaudeUpgradeTestOwner(t, path)
}

func readClaudeUpgradeEnv(t *testing.T, path string) map[string]string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var settings struct {
		Env map[string]string `json:"env"`
	}
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatal(err)
	}
	return settings.Env
}

// Released 1.0.0, 1.0.2, and 1.0.3 routes can have their markers removed and their
// port changed while retaining DefenseClaw's scoped bearer. Setup must not
// leave that credential on the retired listener, even beside an operator route.
func TestClaudeReleasedMarkerlessProductBearerUpgrade(t *testing.T) {
	for _, release := range []string{"1.0.0", "1.0.2", "1.0.3"} {
		for _, goos := range []string{"linux", "darwin", "windows"} {
			for _, proof := range []string{"backup", "sidecar", "generic_backup", "unmatched"} {
				t.Run(release+"/"+goos+"/"+proof, func(t *testing.T) {
					dir := t.TempDir()
					pinClaudeUpgradeTestOwner(t, dir)
					settingsPath := filepath.Join(dir, "settings.json")
					previous := ClaudeCodeSettingsPathOverride
					ClaudeCodeSettingsPathOverride = settingsPath
					t.Cleanup(func() { ClaudeCodeSettingsPathOverride = previous })
					c := NewClaudeCodeConnector()
					earlier := SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:19081", GOOS: goos, sandboxNativeOTLP: true}
					if err := c.Setup(context.Background(), earlier); err != nil {
						t.Fatalf("released %s setup: %v", release, err)
					}
					productToken, err := LoadOTLPPathToken(dir, OTLPScopeClaude)
					if err != nil || productToken == "" {
						t.Fatalf("released scoped token: present=%t err=%v", productToken != "", err)
					}
					backup, err := c.loadBackup(dir)
					if err != nil {
						t.Fatal(err)
					}
					if proof == "sidecar" {
						for key := range backup.ManagedEnv {
							if claudeCodeOTLPHeadersKey(key) {
								delete(backup.ManagedEnv, key)
							}
						}
						if err := c.saveBackup(dir, backup); err != nil {
							t.Fatal(err)
						}
					}
					if proof == "generic_backup" {
						tokenPath, err := OTLPPathTokenFilePath(dir, OTLPScopeClaude)
						if err != nil {
							t.Fatal(err)
						}
						if err := os.Remove(tokenPath); err != nil {
							t.Fatal(err)
						}
					}
					currentToken := productToken
					if proof == "unmatched" {
						currentToken = strings.Repeat("d", 64)
					}
					retired := "http://127.0.0.1:19097/v1/logs"
					data, err := os.ReadFile(settingsPath)
					if err != nil {
						t.Fatal(err)
					}
					var settings map[string]interface{}
					if err := json.Unmarshal(data, &settings); err != nil {
						t.Fatal(err)
					}
					env := settings["env"].(map[string]interface{})
					env["OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"] = retired
					if proof == "generic_backup" {
						delete(env, "OTEL_EXPORTER_OTLP_LOGS_HEADERS")
						env["OTEL_EXPORTER_OTLP_HEADERS"] = "authorization=Bearer " + currentToken + ",x-tenant=logs"
					} else {
						env["OTEL_EXPORTER_OTLP_LOGS_HEADERS"] = "authorization=Bearer " + currentToken + ",x-tenant=logs"
					}
					env["OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"] = "https://collector.example.test/v1/traces"
					env["OTEL_EXPORTER_OTLP_TRACES_HEADERS"] = "x-tenant=traces"
					env["OTEL_TRACES_EXPORTER"] = "otlp"
					writeClaudeUpgradeSettings(t, settingsPath, settings)
					upgrade := earlier
					upgrade.sandboxNativeOTLP = false
					upgrade.APIAddr = "127.0.0.1:19082"
					if err := c.Setup(context.Background(), upgrade); err != nil {
						t.Fatalf("upgrade from %s: %v", release, err)
					}
					got := readClaudeUpgradeEnv(t, settingsPath)
					if got["OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"] != "https://collector.example.test/v1/traces" ||
						got["OTEL_EXPORTER_OTLP_TRACES_HEADERS"] != "x-tenant=traces" ||
						got["OTEL_TRACES_EXPORTER"] != "otlp" || got["CLAUDE_CODE_ENABLE_TELEMETRY"] != "1" {
						t.Fatal("operator traces route changed")
					}
					if proof == "unmatched" {
						if got["OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"] != retired ||
							got["OTEL_EXPORTER_OTLP_LOGS_HEADERS"] != "authorization=Bearer "+currentToken+",x-tenant=logs" {
							t.Fatal("unmatched operator route changed")
						}
						return
					}
					if got["OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"] != "" ||
						got["OTEL_LOGS_EXPORTER"] != "none" ||
						strings.Contains(got["OTEL_EXPORTER_OTLP_LOGS_HEADERS"], productToken) ||
						strings.Contains(got["OTEL_EXPORTER_OTLP_HEADERS"], productToken) {
						t.Fatalf("retired product route or bearer remains: endpoint=%t gate=%q bearer=%t",
							got["OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"] != "", got["OTEL_LOGS_EXPORTER"],
							strings.Contains(got["OTEL_EXPORTER_OTLP_LOGS_HEADERS"], productToken) ||
								strings.Contains(got["OTEL_EXPORTER_OTLP_HEADERS"], productToken))
					}
				})
			}
		}
	}
}

func TestClaudeManagedCleanupUsesProductBearerOnMarkerlessPort(t *testing.T) {
	for _, proof := range []string{"backup", "sidecar", "generic_backup", "unmatched"} {
		t.Run(proof, func(t *testing.T) {
			dir := t.TempDir()
			pinClaudeUpgradeTestOwner(t, dir)
			settingsPath := filepath.Join(dir, "settings.json")
			useClaudeSettings(t, settingsPath)
			productToken := strings.Repeat("b", 64)
			currentToken := productToken
			if proof == "unmatched" {
				currentToken = strings.Repeat("d", 64)
			}
			retired := "http://127.0.0.1:19097/v1/logs"
			env := map[string]string{
				"CLAUDE_CODE_ENABLE_TELEMETRY":     "1",
				"OTEL_LOGS_EXPORTER":               "otlp",
				"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT": retired,
				"OTEL_EXPORTER_OTLP_LOGS_HEADERS":  "authorization=Bearer " + currentToken + ",x-tenant=logs",
			}
			if proof == "generic_backup" {
				delete(env, "OTEL_EXPORTER_OTLP_LOGS_HEADERS")
				env["OTEL_EXPORTER_OTLP_HEADERS"] = "authorization=Bearer " + currentToken + ",x-tenant=logs"
			}
			writeClaudeUpgradeSettings(t, settingsPath, map[string]interface{}{"env": env})
			backup := claudeCodeBackup{ManagedEnv: map[string]string{
				"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT": "http://127.0.0.1:19081/otlp/claudecode/" + productToken + "/v1/logs",
			}}
			if proof != "sidecar" {
				backup.ManagedEnv["OTEL_EXPORTER_OTLP_LOGS_HEADERS"] = "authorization=Bearer " + productToken + ",x-defenseclaw-source=claudecode"
			}
			if err := NewClaudeCodeConnector().saveBackup(dir, backup); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(dir, "hooks"), 0o700); err != nil {
				t.Fatal(err)
			}
			if proof != "generic_backup" {
				if err := os.WriteFile(filepath.Join(dir, "hooks", ".otlp-claudecode.token"), []byte(productToken), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := RemoveUserNativeOTLP("claudecode", SetupOpts{DataDir: dir, ManagedEnterprise: true}); err != nil {
				t.Fatal(err)
			}
			got := readClaudeUpgradeEnv(t, settingsPath)
			if proof == "unmatched" {
				if got["OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"] != retired ||
					got["OTEL_EXPORTER_OTLP_LOGS_HEADERS"] != "authorization=Bearer "+currentToken+",x-tenant=logs" {
					t.Fatal("unmatched operator route changed")
				}
				return
			}
			headersKey := "OTEL_EXPORTER_OTLP_LOGS_HEADERS"
			if proof == "generic_backup" {
				headersKey = "OTEL_EXPORTER_OTLP_HEADERS"
			}
			if got["OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"] != "" ||
				got[headersKey] != "x-tenant=logs" ||
				got["OTEL_LOGS_EXPORTER"] != "" {
				t.Fatalf("managed cleanup kept retired product route or bearer: endpoint=%q headers=%q gate=%q", got["OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"], got[headersKey], got["OTEL_LOGS_EXPORTER"])
			}
		})
	}
}
