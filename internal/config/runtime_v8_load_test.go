// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"gopkg.in/yaml.v3"
)

func TestRuntimeV8LoadersPreserveEmptyConnectorPolicyEntries(t *testing.T) {
	raw := []byte(`config_version: 8
data_dir: /tmp/defenseclaw-v8
guardrail:
  enabled: true
  mode: observe
  connectors:
    codex: {}
    claudecode: {}
observability: {}
`)
	loaders := map[string]func() (*Config, error){
		"activation": func() (*Config, error) {
			return LoadRuntimeV8FromBytes("config.yaml", raw)
		},
		"candidate": func() (*Config, error) {
			return LoadRuntimeV8CandidateFromBytes("config.yaml", raw)
		},
		"inspection-candidate": func() (*Config, error) {
			return LoadRuntimeV8InspectionCandidateFromBytes("config.yaml", raw)
		},
	}
	for name, load := range loaders {
		t.Run(name, func(t *testing.T) {
			cfg, err := load()
			if err != nil {
				t.Fatal(err)
			}
			want := []string{"claudecode", "codex"}
			if got := cfg.ActiveConnectors(); !reflect.DeepEqual(got, want) {
				t.Fatalf("target runtime connectors = %v, want %v", got, want)
			}
		})
	}
}

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

func TestLoadRuntimeV8FileResolvesRelativeDeviceKeyUnderExplicitDataDir(t *testing.T) {
	dir := t.TempDir()
	configuredDataDir := filepath.Join(dir, "state")
	path := filepath.Join(dir, "config.yaml")
	raw := []byte("config_version: 8\ndata_dir: " + configuredDataDir + `
gateway:
  device_key_file: identity/device.key
observability: {}
`)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadRuntimeV8File(path)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(configuredDataDir, "identity", "device.key")
	if cfg.Gateway.DeviceKeyFile != want {
		t.Fatalf("gateway.device_key_file = %q, want %q", cfg.Gateway.DeviceKeyFile, want)
	}
}

func TestLoadRuntimeV8FileResolvesRelativeDeviceKeyAfterDefaultDataDirCompilation(t *testing.T) {
	defaultDataDir := filepath.Join(t.TempDir(), "effective-state")
	t.Setenv("DEFENSECLAW_HOME", defaultDataDir)
	configDir := t.TempDir()
	path := filepath.Join(configDir, "config.yaml")
	raw := []byte(`config_version: 8
gateway:
  device_key_file: identity/device.key
observability: {}
`)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadRuntimeV8File(path)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(defaultDataDir, "identity", "device.key")
	if cfg.Gateway.DeviceKeyFile != want {
		t.Fatalf("gateway.device_key_file = %q, want %q", cfg.Gateway.DeviceKeyFile, want)
	}
}

func TestApplyRuntimeV8DataDirDefaultsRebasesExplicitRelativeDeviceKey(t *testing.T) {
	provisionalDataDir := filepath.Join(t.TempDir(), "provisional-state")
	t.Setenv("DEFENSECLAW_HOME", provisionalDataDir)
	source := filepath.Join(provisionalDataDir, "config.yaml")
	raw := []byte(`config_version: 8
gateway:
  device_key_file: identity/device.key
observability: {}
`)
	cfg, err := LoadRuntimeV8CandidateFromBytes(source, raw)
	if err != nil {
		t.Fatal(err)
	}
	provisionalKey := filepath.Join(provisionalDataDir, "identity", "device.key")
	if cfg.Gateway.DeviceKeyFile != provisionalKey {
		t.Fatalf("provisional gateway.device_key_file = %q, want %q", cfg.Gateway.DeviceKeyFile, provisionalKey)
	}
	finalDataDir := filepath.Join(t.TempDir(), "compiled-state")
	cfg.DataDir = finalDataDir
	if err := ApplyRuntimeV8DataDirDefaultsFromBytes(cfg, source, raw, finalDataDir); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(finalDataDir, "identity", "device.key")
	if cfg.Gateway.DeviceKeyFile != want {
		t.Fatalf("gateway.device_key_file = %q, want %q", cfg.Gateway.DeviceKeyFile, want)
	}
}

func TestResolveRelativeGatewayDeviceKeyFileRejectsNonLocalSpellings(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "state")
	if resolved, ok := ResolveRelativeGatewayDeviceKeyFile(filepath.Join("~", "device.key"), dataDir); !ok || resolved != filepath.Join(dataDir, "~", "device.key") {
		t.Fatalf("literal tilde component resolved to %q, %t", resolved, ok)
	}
	for _, keyFile := range []string{
		"../outside/device.key",
		`C:device.key`,
		`\device.key`,
		"device.key:stream",
	} {
		t.Run(keyFile, func(t *testing.T) {
			if resolved, ok := ResolveRelativeGatewayDeviceKeyFile(keyFile, dataDir); ok {
				t.Fatalf("ResolveRelativeGatewayDeviceKeyFile(%q) = %q, true", keyFile, resolved)
			}
		})
	}
	if resolved, ok := ResolveRelativeGatewayDeviceKeyFile("device.key", "relative-data"); ok {
		t.Fatalf("relative data directory resolved to %q", resolved)
	}
}

func TestLoadRuntimeV8FromBytesRejectsV7BeforeCompatibilityDecode(t *testing.T) {
	_, err := LoadRuntimeV8FromBytes("config.yaml", []byte("config_version: 7\notel:\n  enabled: true\n"))
	if err == nil {
		t.Fatal("v7 compatibility source was accepted by target runtime loader")
	}
}

func TestRuntimeConfigVersionGate(t *testing.T) {
	for _, test := range []struct {
		version int
		want    string
	}{
		{version: 0, want: "config_version 0 is older than 8; run `defenseclaw migrate`"},
		{version: 7, want: "config_version 7 is older than 8; run `defenseclaw migrate`"},
		{version: ObservabilityV8ConfigVersion},
		{version: MaxSupportedConfigVersion},
		{
			version: MaxSupportedConfigVersion + 1,
			want: fmt.Sprintf("config was written by a newer DefenseClaw (config_version %d); "+
				"upgrade DefenseClaw or restore ~/.defenseclaw/previous", MaxSupportedConfigVersion+1),
		},
	} {
		err := checkRuntimeConfigVersion(test.version)
		if test.want == "" {
			if err != nil {
				t.Fatalf("config_version %d rejected: %v", test.version, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), test.want) {
			t.Fatalf("config_version %d error = %v, want %q", test.version, err, test.want)
		}
	}

	// The inspection loader decodes without the YAML entrypoint, so it reaches
	// the runtime gate directly. The gate must report the declared version, not
	// the v7 stamp the compatibility decoder applies to older sources.
	_, err := ResolveObservabilityV8ManagedAIDOptionsForInspection("config.yaml", []byte("config_version: 5\n"))
	if err == nil || !strings.Contains(err.Error(), "config_version 5 is older than 8") {
		t.Fatalf("pre-v8 inspection error = %v, want declared-version migrate guidance", err)
	}
	_, err = ResolveObservabilityV8ManagedAIDOptionsForInspection("config.yaml", []byte("config_version: 10\n"))
	if err == nil || !strings.Contains(err.Error(), "written by a newer DefenseClaw (config_version 10)") {
		t.Fatalf("newer inspection error = %v, want newer-release guidance", err)
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

func TestRuntimeV8LoadsConfigVersion9Keys(t *testing.T) {
	raw := []byte(`config_version: 8
data_dir: /tmp/defenseclaw-v8
admission:
  defaults:
    scan_on_install: false
    actions: {critical: quarantine, low: {install: none, file: none, runtime: disable}}
  skill:
    scanner_overrides: {skill-scanner: {high: block}}
    first_party_allow_list: [{name: codeguard, source_path_contains: [.claude/skills/codeguard]}]
guardrail:
  rule_pack: strict
  rules:
    disable: [ENT-DATA-EMPLOYEE-ID]
    severity_overrides: {SEC-AWS-SECRET: HIGH}
  profiles:
    contractors:
      rules: {severity_overrides: {SEC-OPENAI-V2: LOW}}
asset_policy:
  tool:
    denied: [{name: shell, connector: codex}]
llm_providers:
  custom: [{name: gw, domains: [llm.example.internal], extra_headers: {X-Route: A}}]
update: {check: false}
scanners:
  mcp_scanner: {analyzers: "yara,llm"}
observability: {}
`)
	cfg, err := LoadRuntimeV8FromBytes("config.yaml", raw)
	if err != nil {
		t.Fatal(err)
	}
	admission := cfg.Admission
	if got := admission.Defaults.Actions.Critical.Expand(); got != (SeverityAction{Install: InstallBlock, File: FileActionQuarantine, Runtime: RuntimeDisable}) {
		t.Errorf("critical = %+v, want the quarantine triple", got)
	}
	if got := admission.Defaults.Actions.Low.Expand(); got.Runtime != RuntimeDisable || got.Install != InstallNone {
		t.Errorf("low triple = %+v", got)
	}
	if admission.Defaults.ScanOnInstall == nil || *admission.Defaults.ScanOnInstall {
		t.Errorf("scan_on_install = %v, want false", admission.Defaults.ScanOnInstall)
	}
	if got := admission.Skill.ScannerOverrides["skill-scanner"].High; got == nil || got.Shorthand != AdmissionActionBlock {
		t.Errorf("skill-scanner high = %+v, want block", got)
	}
	// The gateway clones a config through JSON; both action forms survive.
	var cloned AdmissionConfig
	if encoded, err := json.Marshal(admission); err != nil || json.Unmarshal(encoded, &cloned) != nil ||
		!reflect.DeepEqual(cloned, admission) {
		t.Errorf("admission JSON round trip = %+v (%v)", cloned, err)
	}
	if got := cfg.Guardrail.Rules.SeverityOverrides["SEC-AWS-SECRET"]; got != "HIGH" || cfg.Guardrail.RulePack != "strict" {
		t.Errorf("rules = %+v rule_pack = %q; rule IDs must keep their case", cfg.Guardrail.Rules, cfg.Guardrail.RulePack)
	}
	if rules := cfg.Guardrail.Profiles["contractors"].Rules; rules == nil || rules.SeverityOverrides["SEC-OPENAI-V2"] != "LOW" {
		t.Errorf("profile rules = %+v", rules)
	}
	if denied := cfg.AssetPolicy.Tool.Denied; len(denied) != 1 || denied[0] != (AssetPolicyToolRule{Name: "shell", Connector: "codex"}) {
		t.Errorf("asset_policy.tool.denied = %+v", denied)
	}
	if custom := cfg.LLMProviders.Custom; len(custom) != 1 || custom[0].ExtraHeaders["X-Route"] != "A" {
		t.Errorf("llm_providers.custom = %+v", custom)
	}
	if cfg.Update.CheckEnabled() {
		t.Error("update.check false must disable the update notice")
	}
	if got := cfg.Scanners.MCPScanner.Analyzers; !reflect.DeepEqual(got, []string{"yara", "llm"}) {
		t.Errorf("v8 analyzers CSV = %v, want [yara llm]", got)
	}
}

func TestConfigVersion9RejectsReplacedV8Keys(t *testing.T) {
	for path, body := range map[string]string{
		"$.skill_actions": "skill_actions: {}\n",
		"$.guardrail.profiles.p.connectors.codex.rule_pack_dir": "guardrail:\n  profiles:\n    p:\n      connectors:\n        codex: {rule_pack_dir: /x}\n",
		"$.scanners.skill_scanner.use_virustotal":               "scanners:\n  skill_scanner: {use_virustotal: true}\n",
	} {
		for _, version := range []int{8, 9} {
			var document yaml.Node
			if err := yaml.Unmarshal([]byte(fmt.Sprintf("config_version: %d\n%s", version, body)), &document); err != nil {
				t.Fatal(err)
			}
			err := rejectV9RemovedKeys("config.yaml", document.Content[0])
			var yamlErr *V8YAMLError
			switch {
			case version == 8 && err != nil:
				t.Errorf("v8 %s is migration input, got %v", path, err)
			case version == 9 && (!errors.As(err, &yamlErr) || yamlErr.Path != path || yamlErr.Code != V8YAMLErrorLegacyKeyForbidden):
				t.Errorf("v9 %s: got %v", path, err)
			}
		}
	}
}

// A destination key that `defenseclaw keys set` stored in the data dir's .env
// resolves for the candidate validator, as it does for `config validate` and
// the gateway. The 8 -> 9 migration check used to refuse the config of a user
// who had set the key it asked for (GAP-0173).
func TestValidateCandidateResolvesDestinationSecretsFromTheDataDirDotEnv(t *testing.T) {
	const name = "DEFENSECLAW_TEST_GAP0173_KEY"
	dir := t.TempDir()
	raw := []byte("config_version: 9\ndata_dir: " + dir + "\nobservability:\n  destinations:\n" +
		"  - name: galileo\n    kind: otlp\n    preset: galileo\n    enabled: true\n    protocol: http/protobuf\n" +
		"    endpoint: https://api.galileo.ai/otel/traces\n    headers:\n      Galileo-API-Key:\n        env: " + name + "\n" +
		"      project: defenseclaw\n      logstream: production\n" +
		"    send:\n      signals:\n      - traces\n      buckets:\n      - agent.lifecycle\n")
	t.Setenv(name, "")
	if err := os.Unsetenv(name); err != nil {
		t.Fatal(err)
	}
	previous := dotEnvLoader
	t.Cleanup(func() { dotEnvLoader = previous })
	RegisterDotEnvLoader(func(path string) {
		data, err := os.ReadFile(path)
		if err != nil {
			return
		}
		if key, value, ok := strings.Cut(strings.TrimSpace(string(data)), "="); ok && os.Getenv(key) == "" {
			_ = os.Setenv(key, value)
		}
	})

	configFile := filepath.Join(dir, "config.yaml")
	if err := ValidateCandidate(configFile, raw); err == nil || !strings.Contains(err.Error(), name) {
		t.Fatalf("without the key: %v, want an unset-variable error naming %s", err, name)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(name+"=probe\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateCandidate(configFile, raw); err != nil {
		t.Fatalf("with the key in .env: %v", err)
	}
}

// TestRuntimeV8RejectsAdmissionTool: no enforcement path admits a tool
// definition, so admission.tool is not a setting that validates and does
// nothing; tool block/allow is asset_policy.tool.
func TestRuntimeV8RejectsAdmissionTool(t *testing.T) {
	raw := []byte("config_version: 9\nadmission:\n  tool:\n    actions: {medium: block}\nobservability: {}\n")
	if err := ValidateCandidate(filepath.Join(t.TempDir(), "config.yaml"), raw); err == nil {
		t.Fatal("admission.tool loaded; want a validation error")
	}
}
