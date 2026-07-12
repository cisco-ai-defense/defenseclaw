// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestLoadRuntimeV8FromBytesDoesNotRetainLegacyObservability(t *testing.T) {
	t.Setenv("DEFENSECLAW_OTEL_ENABLED", "true")
	raw := []byte(`config_version: 8
data_dir: /tmp/defenseclaw-v8
observability:
  connectors:
    codex:
      webhooks: []
`)
	cfg, err := LoadRuntimeV8FromBytes("config.yaml", raw)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OTel.Enabled || len(cfg.OTel.Destinations) != 0 {
		t.Fatalf("target runtime retained legacy OTel config: %+v", cfg.OTel)
	}
	if cfg.AuditSinks != nil {
		t.Fatalf("target runtime retained global legacy audit sinks: %+v", cfg.AuditSinks)
	}
	if cfg.AIDiscovery.EmitOTel {
		t.Fatal("target runtime retained ai_discovery.emit_otel")
	}
	connector, ok := cfg.Observability.Connectors["codex"]
	if !ok || connector.Webhooks == nil {
		t.Fatalf("v8 connector webhook override was not retained: %+v", cfg.Observability.Connectors)
	}
	if connector.AuditSinks != nil {
		t.Fatalf("target runtime retained connector legacy audit sinks: %+v", connector.AuditSinks)
	}
}

func TestLoadRuntimeV8FileUsesCompiledLocalPaths(t *testing.T) {
	dir := t.TempDir()
	configuredDataDir := filepath.Join(dir, "state")
	path := filepath.Join(dir, "config.yaml")
	raw := []byte("config_version: 8\ndata_dir: " + configuredDataDir + "\nobservability: {}\n")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadRuntimeV8File(path)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"data_dir":                configuredDataDir,
		"audit_db":                filepath.Join(configuredDataDir, DefaultAuditDBName),
		"judge_bodies_db":         filepath.Join(configuredDataDir, DefaultJudgeBodiesDBName),
		"quarantine_dir":          filepath.Join(configuredDataDir, "quarantine"),
		"plugin_dir":              filepath.Join(configuredDataDir, "plugins"),
		"policy_dir":              filepath.Join(configuredDataDir, "policies"),
		"scanners.codeguard":      filepath.Join(configuredDataDir, "codeguard-rules"),
		"ai_discovery.confidence": filepath.Join(configuredDataDir, "confidence.yaml"),
		"firewall.config_file":    filepath.Join(configuredDataDir, "firewall.yaml"),
		"firewall.rules_file":     filepath.Join(configuredDataDir, "firewall.pf.conf"),
		"guardrail.rule_pack_dir": filepath.Join(configuredDataDir, "policies", "guardrail", "default"),
		"gateway.device_key_file": filepath.Join(configuredDataDir, "device.key"),
	}
	got := map[string]string{
		"data_dir":                cfg.DataDir,
		"audit_db":                cfg.AuditDB,
		"judge_bodies_db":         cfg.JudgeBodiesDB,
		"quarantine_dir":          cfg.QuarantineDir,
		"plugin_dir":              cfg.PluginDir,
		"policy_dir":              cfg.PolicyDir,
		"scanners.codeguard":      cfg.Scanners.CodeGuard,
		"ai_discovery.confidence": cfg.AIDiscovery.ConfidencePolicyPath,
		"firewall.config_file":    cfg.Firewall.ConfigFile,
		"firewall.rules_file":     cfg.Firewall.RulesFile,
		"guardrail.rule_pack_dir": cfg.Guardrail.RulePackDir,
		"gateway.device_key_file": cfg.Gateway.DeviceKeyFile,
	}
	for path, expected := range want {
		if got[path] != expected {
			t.Errorf("%s = %q, want %q", path, got[path], expected)
		}
	}
	if cfg.Gateway.APIPort != DefaultGatewayAPIPort {
		t.Errorf("gateway.api_port = %d, want DefaultGatewayAPIPort %d", cfg.Gateway.APIPort, DefaultGatewayAPIPort)
	}
}

func TestLoadRuntimeV8FilePreservesExplicitDataDirDerivedPaths(t *testing.T) {
	dir := t.TempDir()
	configuredDataDir := filepath.Join(dir, "state")
	path := filepath.Join(dir, "config.yaml")
	raw := []byte("config_version: 8\ndata_dir: " + configuredDataDir + `
quarantine_dir: /operator/quarantine
plugin_dir: /operator/plugins
policy_dir: /operator/policies
scanners:
  codeguard: /operator/codeguard
ai_discovery:
  confidence_policy_path: /operator/confidence.yaml
firewall:
  config_file: /operator/firewall.yaml
  rules_file: /operator/firewall.pf.conf
guardrail:
  rule_pack_dir: /operator/rules
gateway:
  device_key_file: /operator/device.key
observability: {}
`)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadRuntimeV8File(path)
	if err != nil {
		t.Fatal(err)
	}
	got := []string{
		cfg.QuarantineDir, cfg.PluginDir, cfg.PolicyDir, cfg.Scanners.CodeGuard,
		cfg.AIDiscovery.ConfidencePolicyPath, cfg.Firewall.ConfigFile, cfg.Firewall.RulesFile,
		cfg.Guardrail.RulePackDir, cfg.Gateway.DeviceKeyFile,
	}
	want := []string{
		"/operator/quarantine", "/operator/plugins", "/operator/policies", "/operator/codeguard",
		"/operator/confidence.yaml", "/operator/firewall.yaml", "/operator/firewall.pf.conf",
		"/operator/rules", "/operator/device.key",
	}
	for index := range want {
		if got[index] != want[index] {
			t.Errorf("explicit path %d = %q, want %q", index, got[index], want[index])
		}
	}
}

func TestLoadRuntimeV8FromBytesRejectsV7BeforeCompatibilityDecode(t *testing.T) {
	_, err := LoadRuntimeV8FromBytes("config.yaml", []byte("config_version: 7\notel:\n  enabled: true\n"))
	if err == nil {
		t.Fatal("v7 compatibility source was accepted by target runtime loader")
	}
}

func TestRuntimeV8LoadersRetainManagedPathTrust(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "config.yaml")
	raw := []byte("config_version: 8\ndata_dir: " + directory + "\nobservability: {}\n")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(managed.DeploymentModeEnv, managed.DeploymentModeManagedEnterprise)

	loaders := map[string]func() error{
		"file": func() error {
			_, err := LoadRuntimeV8File(path)
			return err
		},
		"activation-bytes": func() error {
			_, err := LoadRuntimeV8FromBytes(path, raw)
			return err
		},
		"reload-candidate-bytes": func() error {
			_, err := LoadRuntimeV8CandidateFromBytes(path, raw)
			return err
		},
	}
	for name, load := range loaders {
		t.Run(name, func(t *testing.T) {
			err := load()
			if err == nil || !strings.Contains(err.Error(), "managed_enterprise config trust check failed") {
				t.Fatalf("managed runtime loader error = %v, want authoritative path trust refusal", err)
			}
		})
	}
}
