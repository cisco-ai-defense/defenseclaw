// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

func TestCodexPerUserUpgradeRevokesNativeExporterWithoutRemovingOperatorOTel(t *testing.T) {
	for _, managed := range []bool{false, true} {
		for _, goos := range []string{"linux", "darwin", "windows"} {
			name := goos + "/per-user"
			if managed {
				name = goos + "/managed"
			}
			t.Run(name, func(t *testing.T) {
				dir := t.TempDir()
				configPath := filepath.Join(dir, "config.toml")
				original := "model = \"gpt-5\"\n[otel]\nlog_user_prompt = false\n" +
					"[otel.exporter.otlp-http]\nendpoint = \"https://collector.example.test/v1/logs\"\nprotocol = \"json\"\n"
				if err := os.WriteFile(configPath, []byte(original), 0o600); err != nil {
					t.Fatal(err)
				}
				prior := CodexConfigPathOverride
				CodexConfigPathOverride = configPath
				t.Cleanup(func() { CodexConfigPathOverride = prior })

				c := NewCodexConnector()
				opts := SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:19081", APIToken: "test-hook-token", GOOS: goos, ManagedEnterprise: managed}
				earlier := opts
				earlier.ManagedEnterprise = true // render the earlier native exporter
				earlier.sandboxNativeOTLP = true
				if err := c.Setup(context.Background(), earlier); err != nil {
					t.Fatalf("earlier setup: %v", err)
				}
				token, err := LoadOTLPPathToken(dir, OTLPScopeCodex)
				if err != nil || token == "" {
					t.Fatalf("earlier scoped token: present=%t err=%v", token != "", err)
				}
				if err := c.Setup(context.Background(), opts); err != nil {
					t.Fatalf("upgrade setup: %v", err)
				}
				data, err := os.ReadFile(configPath)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(data), token) {
					t.Fatalf("old native credential remains in config: %s", data)
				}
				var config map[string]interface{}
				if err := toml.Unmarshal(data, &config); err != nil {
					t.Fatal(err)
				}
				otel, ok := config["otel"].(map[string]interface{})
				if !ok || otel["log_user_prompt"] != false {
					t.Fatalf("operator OTel block was lost: %+v", config["otel"])
				}
				exporter, _ := otel["exporter"].(map[string]interface{})
				http, _ := exporter["otlp-http"].(map[string]interface{})
				if http["endpoint"] != "https://collector.example.test/v1/logs" {
					t.Fatalf("operator collector was not restored: %+v", http)
				}
				if token, err := LoadOTLPPathToken(dir, OTLPScopeCodex); err != nil || token != "" {
					t.Fatalf("obsolete token remains: present=%t err=%v", token != "", err)
				}
			})
		}
	}
}

// Released 0.8.10 and 1.0.0-1.0.3 per-user Codex setups wrote unscoped
// /v1/<signal> URLs with the paired product headers. An API port change during
// upgrade must not strand their bearer on a listener another account can hold.
func TestCodexReleasedNativeExporterUpgradeAcrossOS(t *testing.T) {
	for _, release := range []string{"0.8.10", "1.0.0-1.0.3"} {
		for _, goos := range []string{"linux", "darwin", "windows"} {
			t.Run(release+"/"+goos, func(t *testing.T) {
				dir := t.TempDir()
				configPath := filepath.Join(dir, "config.toml")
				original := "model = \"gpt-5\"\n[otel]\nlog_user_prompt = false\n" +
					"[otel.exporter.otlp-http]\nendpoint = \"https://collector.example.test/v1/logs\"\nprotocol = \"json\"\n"
				if err := os.WriteFile(configPath, []byte(original), 0o600); err != nil {
					t.Fatal(err)
				}
				prior := CodexConfigPathOverride
				CodexConfigPathOverride = configPath
				t.Cleanup(func() { CodexConfigPathOverride = prior })
				c := NewCodexConnector()
				// Use the per-user path to save the operator's preimage. Current
				// managed Windows Setup must run through the machine installer;
				// the released per-user OTEL shape is written below.
				earlier := SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:19081", APIToken: "test-hook-token", GOOS: goos}
				if err := c.Setup(context.Background(), earlier); err != nil {
					t.Fatalf("seed earlier setup backup: %v", err)
				}
				var cfg map[string]interface{}
				data, err := os.ReadFile(configPath)
				if err != nil {
					t.Fatal(err)
				}
				if err := toml.Unmarshal(data, &cfg); err != nil {
					t.Fatal(err)
				}
				legacy := map[string]interface{}{"environment": "dev", "log_user_prompt": true}
				for key, signal := range map[string]string{"exporter": "logs", "trace_exporter": "traces", "metrics_exporter": "metrics"} {
					legacy[key] = map[string]interface{}{"otlp-http": map[string]interface{}{
						"endpoint": "http://127.0.0.1:19081/v1/" + signal,
						"protocol": "json",
						"headers": map[string]interface{}{
							"authorization":        "Bearer released-static-token",
							"x-defenseclaw-source": "codex",
							"x-defenseclaw-client": "codex-otel/1.0",
						},
					}}
				}
				cfg["otel"] = legacy
				data, err = toml.Marshal(cfg)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(configPath, data, 0o600); err != nil {
					t.Fatal(err)
				}
				upgrade := earlier
				upgrade.APIAddr = "127.0.0.1:19082"
				upgrade.ManagedEnterprise = false
				if err := c.Setup(context.Background(), upgrade); err != nil {
					t.Fatalf("per-user upgrade: %v", err)
				}
				data, err = os.ReadFile(configPath)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(data), "released-static-token") || strings.Contains(string(data), "http://127.0.0.1:19081/") {
					t.Fatal("released native exporter or credential survived the port change")
				}
				cfg = nil
				if err := toml.Unmarshal(data, &cfg); err != nil {
					t.Fatal(err)
				}
				otel, _ := cfg["otel"].(map[string]interface{})
				exporter, _ := otel["exporter"].(map[string]interface{})
				http, _ := exporter["otlp-http"].(map[string]interface{})
				if otel["log_user_prompt"] != false || http["endpoint"] != "https://collector.example.test/v1/logs" {
					t.Fatal("operator OTel preimage was not restored")
				}
			})
		}
	}
}
