// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A released exporter with only one product marker is ambiguous after a port
// change. Setup must stop before it leaves a bearer aimed at the retired port.
func TestCodexUpgradeRefusesPartialMarkerOnRetiredPort(t *testing.T) {
	for _, release := range []string{"1.0.2", "1.0.3"} {
		for _, goos := range []string{"linux", "darwin", "windows"} {
			for _, retained := range []string{"source", "client"} {
				t.Run(release+"/"+goos+"/"+retained, func(t *testing.T) {
					dir := t.TempDir()
					configPath := filepath.Join(dir, "config.toml")
					if err := os.WriteFile(configPath, []byte("model = 'gpt-5'\n"), 0o600); err != nil {
						t.Fatal(err)
					}
					prior := CodexConfigPathOverride
					CodexConfigPathOverride = configPath
					defer func() { CodexConfigPathOverride = prior }()
					c := NewCodexConnector()
					earlier := SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:19081", APIToken: "test-hook-token", GOOS: goos}
					if err := c.Setup(context.Background(), earlier); err != nil {
						t.Fatalf("seed setup backup: %v", err)
					}
					base, err := os.ReadFile(configPath)
					if err != nil {
						t.Fatal(err)
					}
					fixture, err := os.ReadFile(filepath.Join("testdata", "codex_otel_"+release+"_product.toml"))
					if err != nil {
						t.Fatal(err)
					}
					removedMarker := "x-defenseclaw-client = 'codex-otel/1.0'\n"
					if retained == "client" {
						removedMarker = "x-defenseclaw-source = 'codex'\n"
					}
					body := strings.ReplaceAll(string(fixture), "\r\n", "\n")
					body = strings.ReplaceAll(body, removedMarker, "")
					if goos == "windows" {
						body = strings.ReplaceAll(body, "\n", "\r\n")
					}
					before := append(base, []byte(body)...)
					if err := os.WriteFile(configPath, before, 0o600); err != nil {
						t.Fatal(err)
					}
					upgrade := earlier
					upgrade.APIAddr = "127.0.0.1:19082"
					if err := c.Setup(context.Background(), upgrade); err == nil || !strings.Contains(err.Error(), "otel.exporter") {
						t.Fatalf("Setup did not report ambiguous retired-port exporter: %v", err)
					}
					got, err := os.ReadFile(configPath)
					if err != nil || string(got) != string(before) {
						t.Fatalf("refused Setup changed the Codex config: %v", err)
					}
					if err := c.VerifyClean(upgrade); err == nil || !strings.Contains(err.Error(), "otel.exporter.otlp-http.endpoint") {
						t.Fatalf("VerifyClean did not name the stale endpoint: %v", err)
					}
					if _, err := UserNativeOTLPResidue("codex", SetupOpts{DataDir: dir, ManagedEnterprise: true}); err == nil || !strings.Contains(err.Error(), "otel.exporter") {
						t.Fatalf("managed cleanup accepted ambiguous retired-port exporter: %v", err)
					}
				})
			}
		}
	}
}
