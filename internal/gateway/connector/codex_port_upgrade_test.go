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
	for _, goos := range []string{"linux", "darwin", "windows"} {
		t.Run(goos, func(t *testing.T) {
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
			opts := SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:19081", APIToken: "test-hook-token", GOOS: goos}
			earlier := opts
			earlier.ManagedEnterprise = true // render the earlier native exporter
			if err := c.Setup(context.Background(), earlier); err != nil {
				t.Fatalf("earlier setup: %v", err)
			}
			token, err := LoadOTLPPathToken(dir, OTLPScopeCodex)
			if err != nil || token == "" {
				t.Fatalf("earlier scoped token: present=%t err=%v", token != "", err)
			}
			if err := c.Setup(context.Background(), opts); err != nil {
				t.Fatalf("per-user upgrade setup: %v", err)
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
