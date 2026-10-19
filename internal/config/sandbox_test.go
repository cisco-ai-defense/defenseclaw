// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestSandboxCommonSourceCorpus(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "sandbox", "common_config_cases.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases []struct {
			Name, Source, Path string
			Valid              bool
		}
	}
	if err := yaml.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, tc := range corpus.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), DefaultConfigName)
			version := "9"
			if tc.Name == "secure_client_namespace_is_frozen" {
				version = "8"
			}
			err := ValidateCandidate(path, []byte("config_version: "+version+"\n"+tc.Source))
			if (err == nil) != tc.Valid {
				t.Fatalf("valid=%v, error=%v", tc.Valid, err)
			}
			if tc.Path != "" && err != nil && !strings.Contains(err.Error(), tc.Path) {
				t.Fatalf("error=%v, want field %s", err, tc.Path)
			}
		})
	}
}

func TestSandboxCommonDefaultsAndExplicitEnablement(t *testing.T) {
	legacy := &Config{OpenShell: OpenShellConfig{Enabled: true}}
	if legacy.Sandbox != nil || legacy.SandboxDefaultRuntime() != "auto" || !legacy.SandboxRuntimeEnabled("openshell") || legacy.SandboxRuntimeEnabled("axis") {
		t.Fatal("legacy runtime behavior changed")
	}
	cfg := &Config{OpenShell: legacy.OpenShell}
	if err := restoreSandboxConfig(cfg, []byte("sandbox: {runtime: axis, enabled: true}\n"), t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if cfg.SandboxDefaultRuntime() != "axis" || !cfg.SandboxEnabled() || cfg.SandboxRuntimeEnabled("axis") || cfg.SandboxRuntimeEnabled("openshell") {
		t.Fatal("a runtime was implicitly enabled")
	}
	cfg.Sandbox.Runtimes.AXIS.Enabled = true
	if !cfg.SandboxRuntimeEnabled("axis") || cfg.SandboxRuntimeEnabled("foreign") {
		t.Fatal("explicit lane enablement was not respected")
	}
	cfg.Sandbox.Enabled = false
	if cfg.SandboxRuntimeEnabled("axis") || cfg.SandboxRuntimeEnabled("openshell") {
		t.Fatal("common off switch did not disable all runtimes")
	}
}

func TestSandboxCommonProjectionPreservesVendorAndAdministrativeState(t *testing.T) {
	f := false
	cfg := &Config{OpenShell: OpenShellConfig{
		Binary: "/trusted/openshell", Gateway: OpenShellGatewayConfig{Name: "team"},
		Image: OpenShellImageConfig{Base: "trusted-base"},
		Admin: OpenShellAdminConfig{AllowYolo: &f, MinProfile: "strict", RequiredFor: []string{"claudecode"}},
	}}
	before := cfg.OpenShell
	if err := restoreSandboxConfig(cfg, []byte("sandbox: {enabled: true, llm: none, admin: {process_tree: true}}\n"), "/state"); err != nil {
		t.Fatal(err)
	}
	got, err := cfg.EffectiveSandboxPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if got.Binary != before.Binary || got.Gateway != before.Gateway || got.Image.Base != before.Image.Base || got.LLM != "none" {
		t.Fatal("projection changed vendor settings or ignored common policy")
	}
	if got.Admin.AllowYolo == nil || *got.Admin.AllowYolo || got.Admin.MinProfile != "strict" || got.Admin.ProcessTree == nil || !*got.Admin.ProcessTree {
		t.Fatalf("administrative floor weakened: %+v", got.Admin)
	}
	if !reflect.DeepEqual(cfg.OpenShell, before) {
		t.Fatal("projection mutated the source configuration")
	}
}

func TestSandboxCommonRoundTrip(t *testing.T) {
	cfg := Config{Sandbox: defaultSandboxConfig("/state")}
	cfg.Sandbox.Enabled, cfg.Sandbox.Runtime = true, "axis"
	cfg.Sandbox.Runtimes.AXIS.Enabled = true
	f := false
	cfg.Sandbox.MCP.Import = &f
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var again Config
	if err := yaml.Unmarshal(raw, &again); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg.Sandbox, again.Sandbox) {
		t.Fatal("common policy did not round-trip")
	}
	if !strings.Contains(string(raw), "import: false") || strings.Contains(string(raw), "import_:") {
		t.Fatal("mcp.import YAML key changed")
	}
}

func TestSandboxCommonRuntimeSelectionPreservesLegacyPolicy(t *testing.T) {
	cfg := &Config{OpenShell: OpenShellConfig{
		Egress:    OpenShellEgressConfig{Block: []string{"blocked.example"}, Allow: []string{"allowed.example"}},
		Workdir:   OpenShellWorkdirConfig{Masks: []string{".secret"}, GitDepth: 17},
		Harnesses: []string{"claudecode"}, Profile: "strict",
	}}
	for _, source := range []string{
		"sandbox: {enabled: true, runtime: axis, runtimes: {axis: {enabled: true}}}\n",
		"sandbox: {runtime: axis, egress: {ports: [443]}, workdir: {git_depth: 0}}\n",
	} {
		if err := restoreSandboxConfig(cfg, []byte(source), "/state"); err != nil {
			t.Fatal(err)
		}
		got, err := cfg.EffectiveSandboxPolicy()
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got.Egress.Block, cfg.OpenShell.Egress.Block) || !reflect.DeepEqual(got.Egress.Allow, cfg.OpenShell.Egress.Allow) ||
			!reflect.DeepEqual(got.Workdir.Masks, cfg.OpenShell.Workdir.Masks) || !reflect.DeepEqual(got.Harnesses, cfg.OpenShell.Harnesses) || got.Profile != "strict" {
			t.Fatalf("runtime selection dropped legacy policy: %+v", got)
		}
		if strings.Contains(source, "git_depth: 0") && got.Workdir.GitDepth != 0 {
			t.Fatal("explicit common zero was replaced by a default")
		}
	}
	cfg.Sandbox = &SandboxConfig{Enabled: true, Runtime: "axis"}
	got, err := cfg.EffectiveSandboxPolicy()
	if err != nil || !reflect.DeepEqual(got.Egress, cfg.OpenShell.Egress) || !reflect.DeepEqual(got.Workdir, cfg.OpenShell.Workdir) || !reflect.DeepEqual(got.Harnesses, cfg.OpenShell.Harnesses) {
		t.Fatalf("programmatic runtime selection dropped legacy policy: %v, %v", got, err)
	}
}

func TestSandboxCommonLoadedPolicyReachesExistingConsumers(t *testing.T) {
	for _, tc := range []struct {
		name, common string
		enabled      bool
	}{
		{"off", "{enabled: false, runtime: axis}", false},
		{"lane_off", "{enabled: true, runtime: openshell}", false},
		{"on", "{enabled: true, runtime: openshell, runtimes: {openshell: {enabled: true}}, llm: none, harnesses: [claudecode]}", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte("config_version: 9\nopenshell: {enabled: true, pack_dir: '', egress: {block: [blocked.example]}, workdir: {masks: [.secret]}}\nsandbox: " + tc.common + "\n")
			cfg, err := LoadRuntimeV8InspectionCandidateFromBytes(filepath.Join(t.TempDir(), DefaultConfigName), raw)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.OpenShell.Enabled != tc.enabled || cfg.OpenShell.PackDir != "" || !reflect.DeepEqual(cfg.OpenShell.Egress.Block, []string{"blocked.example"}) ||
				!reflect.DeepEqual(cfg.OpenShell.Workdir.Masks, []string{".secret"}) {
				t.Fatalf("existing consumer received wrong policy: %+v", cfg.OpenShell)
			}
			if tc.enabled && (cfg.OpenShell.LLM != "none" || !reflect.DeepEqual(cfg.PolicyConnectors(), []string{"claudecode", "openclaw"})) {
				t.Fatalf("common policy did not reach existing consumers: llm=%s connectors=%v", cfg.OpenShell.LLM, cfg.PolicyConnectors())
			}
		})
	}
}

func TestSandboxCommonLoadedYAMLRoundTripAndDeepCopyKeepInheritedPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultConfigName)
	raw := []byte(`config_version: 9
openshell:
  enabled: true
  egress: {block: [blocked.example], allow: [allowed.example]}
  workdir: {masks: [.secret], git_depth: 17}
  harnesses: [claudecode]
sandbox: {runtime: openshell}
`)
	cfg, err := LoadRuntimeV8InspectionCandidateFromBytes(path, raw)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Sandbox.Workdir.GitDepth != 17 || !reflect.DeepEqual(cfg.Sandbox.Egress.Block, []string{"blocked.example"}) ||
		!reflect.DeepEqual(cfg.Sandbox.Workdir.Masks, []string{".secret"}) || !reflect.DeepEqual(cfg.Sandbox.Harnesses, []string{"claudecode"}) {
		t.Fatalf("loaded common model omitted inherited restrictions: %+v", cfg.Sandbox)
	}
	cloned, err := cfg.DeepCopy()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg.Sandbox, cloned.Sandbox) {
		t.Fatal("DeepCopy changed common configuration or source presence")
	}
	cloned.Sandbox.declared["workdir.git_depth"] = true
	if cfg.Sandbox.declared["workdir.git_depth"] {
		t.Fatal("DeepCopy shares common source-presence metadata")
	}
	cloned.Sandbox.Workdir.Masks[0] = "changed"
	if cfg.Sandbox.Workdir.Masks[0] != ".secret" {
		t.Fatal("DeepCopy shares inherited workspace restrictions")
	}
	before, err := cfg.EffectiveSandboxPolicy()
	if err != nil {
		t.Fatal(err)
	}
	serialized, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Runtime Config includes unrelated derived v8 fields (for example
	// guardrail.rule_pack_dir) that a v9 source writer omits. Round-trip the
	// exact serialized sandbox sections through a canonical source document,
	// as the node-level config writer does, rather than treating the entire
	// runtime object as source intent.
	var emitted map[string]any
	if err := yaml.Unmarshal(serialized, &emitted); err != nil {
		t.Fatal(err)
	}
	serialized, err = yaml.Marshal(map[string]any{
		"config_version": 9, "openshell": emitted["openshell"], "sandbox": emitted["sandbox"],
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateCandidate(path, serialized); err != nil {
		t.Fatalf("serialized sandbox sections conflict or fail source validation: %v", err)
	}
	reloaded, err := LoadRuntimeV8InspectionCandidateFromBytes(path, serialized)
	if err != nil {
		t.Fatalf("serialized loaded configuration cannot reload: %v", err)
	}
	after, err := reloaded.EffectiveSandboxPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("loaded YAML round-trip changed sandbox policy:\nbefore=%+v\nafter=%+v", before, after)
	}
}

func TestSandboxCommonLoaderErrorsIdentifySettingsWithoutValues(t *testing.T) {
	for _, tc := range []struct {
		name, source, path, rule string
	}{
		{"axis_unavailable", "sandbox: {enabled: true, runtime: axis}\n", "sandbox.runtime", "AXIS runtime is not available"},
		{"explicit_overlap", "openshell: {workdir: {masks: [private-left-canary]}}\nsandbox: {workdir: {masks: [private-right-canary]}}\n", "sandbox.workdir.masks", "conflicts"},
		{"profile_floor", "sandbox: {admin: {allowed_harnesses: [codex]}}\nguardrail: {profiles: {developers: {sandbox: {required_for: [claudecode]}}}}\n", `guardrail.profiles["developers"]`, "outside allowed_harnesses"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadRuntimeV8InspectionCandidateFromBytes(filepath.Join(t.TempDir(), DefaultConfigName), []byte("config_version: 9\n"+tc.source))
			var setting *SettingError
			if !errors.As(err, &setting) || setting.Path != tc.path || !strings.Contains(setting.Detail(), tc.rule) {
				t.Fatalf("loader error=%v, setting=%+v; want path=%s rule=%s", err, setting, tc.path, tc.rule)
			}
			if strings.Contains(setting.Detail(), "private-left-canary") || strings.Contains(setting.Detail(), "private-right-canary") {
				t.Fatal("conflicting source values leaked into the diagnostic rule")
			}
		})
	}
}

func TestSandboxCommonTypedErrorsDoNotReplaceSchemaOrYAMLDiagnostics(t *testing.T) {
	for _, source := range []string{
		"config_version: 9\nsandbox: {runtime: unknown}\n",
		"config_version: 9\nsandbox: {enabled: [unterminated\n",
	} {
		err := ValidateCandidate(filepath.Join(t.TempDir(), DefaultConfigName), []byte(source))
		var setting *SettingError
		var schemaError *V8SchemaError
		var yamlError *V8YAMLError
		if errors.As(err, &setting) || (!errors.As(err, &schemaError) && !errors.As(err, &yamlError)) {
			t.Fatalf("source diagnostic replaced by common semantic error: %v", err)
		}
	}
}
