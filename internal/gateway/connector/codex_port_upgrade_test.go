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

func TestCodexUpgradeKeepsOperatorAuthorizationOnChangedCollector(t *testing.T) {
	for _, release := range []string{"1.0.2", "1.0.3"} {
		for _, goos := range []string{"linux", "darwin", "windows"} {
			t.Run(release+"/"+goos, func(t *testing.T) {
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
					t.Fatal(err)
				}
				base, err := os.ReadFile(configPath)
				if err != nil {
					t.Fatal(err)
				}
				for _, auth := range []struct{ name, value, want string }{
					{"product", "product", ""},
					{"operator", "Bearer operator-collector-token", "Bearer operator-collector-token"},
				} {
					for _, cleanup := range []string{"setup", "managed_cleanup"} {
						t.Run(auth.name+"/"+cleanup, func(t *testing.T) {
							productToken, err := EnsureOTLPPathToken(dir, OTLPScopeCodex)
							if err != nil {
								t.Fatal(err)
							}
							value := auth.value
							if value == "product" {
								value = "Bearer " + productToken
							}
							config := string(base) + "\n[otel.exporter.otlp-http]\nendpoint = 'https://operator.example.test/v1/logs'\nprotocol = 'json'\n[otel.exporter.otlp-http.headers]\nauthorization = '" + value + "'\nx-defenseclaw-source = 'codex'\nx-defenseclaw-client = 'codex-otel/1.0'\n"
							if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
								t.Fatal(err)
							}
							upgrade := earlier
							upgrade.APIAddr = "127.0.0.1:19082"
							if cleanup == "setup" {
								if err := c.Setup(context.Background(), upgrade); err != nil {
									t.Fatal(err)
								}
							} else {
								if _, err := RemoveUserNativeOTLP("codex", SetupOpts{DataDir: dir, ManagedEnterprise: true}); err != nil {
									t.Fatal(err)
								}
							}
							data, err := os.ReadFile(configPath)
							if err != nil {
								t.Fatal(err)
							}
							var parsed map[string]interface{}
							if err := toml.Unmarshal(data, &parsed); err != nil {
								t.Fatal(err)
							}
							exporter := parsed["otel"].(map[string]interface{})["exporter"]
							http := exporter.(map[string]interface{})["otlp-http"].(map[string]interface{})
							headers, _ := http["headers"].(map[string]interface{})
							gotAuth, _ := headers["authorization"].(string)
							if http["endpoint"] != "https://operator.example.test/v1/logs" || gotAuth != auth.want {
								t.Fatalf("collector or authorization changed: endpoint=%v auth_matches=%t", http["endpoint"], gotAuth == auth.want)
							}
							if _, exists := headers["x-defenseclaw-source"]; exists {
								t.Fatal("product marker survived")
							}
							if residue, err := UserNativeOTLPResidue("codex", SetupOpts{DataDir: dir, ManagedEnterprise: true}); err != nil || len(residue) != 0 {
								t.Fatalf("cleanup left native OTLP residue: %v, %v", residue, err)
							}
						})
					}
				}
			})
		}
	}
}

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
				earlier := SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:19081", APIToken: "test-hook-token", GOOS: goos, ManagedEnterprise: true}
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

// The 1.0.2 and 1.0.3 renderers wrote the same three marked /v1/<signal>
// exporters. Upgrade may remove that product table. If the operator replaced
// it after setup, the hook refresh must retain the replacement's exact bytes,
// including a standalone prompt-capture preference without any exporter.
func TestCodexReleasedOtelUpgradePreservesOperatorBytes(t *testing.T) {
	for _, release := range []string{"1.0.2", "1.0.3"} {
		for _, goos := range []string{"linux", "darwin", "windows"} {
			for _, owner := range []string{"product", "user_edited", "user_preference"} {
				t.Run(release+"/"+goos+"/"+owner, func(t *testing.T) {
					dir := t.TempDir()
					configPath := filepath.Join(dir, "config.toml")
					if err := os.WriteFile(configPath, []byte("model = 'gpt-5'\n"), 0o600); err != nil {
						t.Fatal(err)
					}
					prior := CodexConfigPathOverride
					CodexConfigPathOverride = configPath
					t.Cleanup(func() { CodexConfigPathOverride = prior })

					c := NewCodexConnector()
					earlier := SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:19081", APIToken: "test-hook-token", GOOS: goos, CodexOtelEnvironment: goos}
					if err := c.Setup(context.Background(), earlier); err != nil {
						t.Fatalf("seed released setup backup: %v", err)
					}
					base, err := os.ReadFile(configPath)
					if err != nil {
						t.Fatal(err)
					}
					fixturePath := filepath.Join("testdata", "codex_otel_"+release+"_"+owner+".toml")
					fixture, err := os.ReadFile(fixturePath)
					if err != nil {
						t.Fatal(err)
					}
					fixture = []byte(strings.ReplaceAll(string(fixture), "fixture-os", goos))
					if goos == "windows" {
						windowsLines := func(data []byte) []byte {
							return []byte(strings.ReplaceAll(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n", "\r\n"))
						}
						fixture = windowsLines(fixture)
						base = windowsLines(base)
					}
					if err := os.WriteFile(configPath, append(base, fixture...), 0o600); err != nil {
						t.Fatal(err)
					}
					upgrade := earlier
					upgrade.APIAddr = "127.0.0.1:19082" // ownership must survive a port change
					if err := c.Setup(context.Background(), upgrade); err != nil {
						t.Fatalf("upgrade: %v", err)
					}
					got, err := os.ReadFile(configPath)
					if err != nil {
						t.Fatal(err)
					}
					if owner == "product" {
						var parsed map[string]interface{}
						if err := toml.Unmarshal(got, &parsed); err != nil {
							t.Fatal(err)
						}
						_, retained := parsed["otel"]
						if retained || strings.Contains(string(got), "released-static-token") {
							t.Fatalf("released product exporter survived upgrade:\n%s", got)
						}
					} else if !strings.Contains(string(got), string(fixture)) {
						t.Fatalf("operator [otel] bytes changed during hook upgrade; want:\n%s\ngot:\n%s", fixture, got)
					}
				})
			}
		}
	}
}
