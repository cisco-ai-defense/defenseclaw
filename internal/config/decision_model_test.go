// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func writeDecisionModelConfig(t *testing.T, version int, section string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, DefaultConfigName)
	raw := "config_version: " + string(rune('0'+version)) + "\ndata_dir: " + dir + "\n" + section
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDecisionModelDefaultsOff(t *testing.T) {
	for _, version := range []int{8, 9} {
		cfg, err := LoadFromFile(writeDecisionModelConfig(t, version, ""))
		if err != nil {
			t.Fatalf("v%d: LoadFromFile: %v", version, err)
		}
		d := cfg.DecisionModel
		if d.Enabled || d.Active() {
			t.Fatalf("v%d: decision_model must default to off: %+v", version, d)
		}
		if d.EffectiveAllowThreshold() != 0.30 || d.EffectiveBlockThreshold() != 0.75 ||
			d.EffectiveTimeoutSeconds() != 1 || d.EffectiveOnConfidentBlock() != DecisionModelEscalate ||
			d.EffectiveAPIKeyEnv() != DefenseClawDecisionModelKeyEnv || d.EffectiveProtocol() != DecisionModelProtocolSystemOne {
			t.Fatalf("v%d: effective defaults = %+v", version, d)
		}
	}
}

func TestDecisionModelLoadsEnabledBlock(t *testing.T) {
	cfg, err := LoadFromFile(writeDecisionModelConfig(t, 9, `decision_model:
  enabled: true
  model: openjev
  base_url: http://127.0.0.1:8791/v1/systemone
  timeout: 2
  allow_threshold: 0.2
  block_threshold: 0.8
  on_confident_block: decide
`))
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	d := cfg.DecisionModel
	if !d.Active() || d.Model != "openjev" || d.EffectiveAllowThreshold() != 0.2 ||
		d.EffectiveBlockThreshold() != 0.8 || d.EffectiveOnConfidentBlock() != DecisionModelDecide ||
		d.EffectiveTimeoutSeconds() != 2 {
		t.Fatalf("decision_model = %+v", d)
	}
}

func TestDecisionModelLoadRefusesBadBlock(t *testing.T) {
	cases := map[string]string{
		"remote http":     "decision_model:\n  enabled: true\n  model: m\n  base_url: http://10.1.2.3:8791/v1/systemone\n",
		"no url":          "decision_model:\n  enabled: true\n  model: m\n",
		"no model":        "decision_model:\n  enabled: true\n  base_url: https://dm.example/v1/systemone\n",
		"inverted":        "decision_model:\n  allow_threshold: 0.8\n  block_threshold: 0.5\n",
		"bad mode":        "decision_model:\n  on_confident_block: maybe\n",
		"url credentials": "decision_model:\n  base_url: https://user:pw@dm.example/v1/systemone\n",
		"bad protocol":    "decision_model:\n  protocol: openai\n",
	}
	for name, section := range cases {
		if _, err := LoadFromFile(writeDecisionModelConfig(t, 9, section)); err == nil {
			t.Errorf("%s: load accepted %q", name, section)
		}
	}
}

func TestDecisionModelSchema(t *testing.T) {
	good := "config_version: 9\ndecision_model:\n  enabled: true\n  model: openjev\n  base_url: http://127.0.0.1:8791/v1/systemone\n  api_key_env: DM_KEY\n  timeout: 2.5\n  allow_threshold: 0.3\n  block_threshold: 0.75\n  on_confident_block: escalate\n"
	if err := ValidateV8SchemaBytes("config.yaml", []byte(good)); err != nil {
		t.Fatalf("schema refused a valid block: %v", err)
	}
	// A literal key has no field: the token lives in the environment.
	bad := "config_version: 9\ndecision_model:\n  api_key: literal\n"
	if err := ValidateV8SchemaBytes("config.yaml", []byte(bad)); err == nil {
		t.Fatal("schema accepted decision_model.api_key")
	}
}

// TestDecisionModelProtocol: protocol is a closed set, case-folded, and an
// existing block without it keeps speaking System One.
func TestDecisionModelProtocol(t *testing.T) {
	cfg, err := LoadFromFile(writeDecisionModelConfig(t, 9, `decision_model:
  enabled: true
  model: gemini-decision-1
  base_url: https://generativelanguage.googleapis.com/v1beta/decisions
  protocol: gemini-decisions
  api_key_env: GEMINI_API_KEY
`))
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	if got := cfg.DecisionModel.EffectiveProtocol(); got != DecisionModelProtocolGeminiDecisions {
		t.Fatalf("protocol = %q", got)
	}
	for _, p := range []string{"", "system-one", " SYSTEM-ONE ", "gemini-decisions"} {
		if err := (DecisionModelConfig{Protocol: p}).Validate(); err != nil {
			t.Errorf("protocol %q refused: %v", p, err)
		}
	}
	for _, p := range []string{"gemini", "openai", "systemone"} {
		if err := (DecisionModelConfig{Protocol: p}).Validate(); err == nil {
			t.Errorf("protocol %q accepted", p)
		}
	}
	good := "config_version: 9\ndecision_model:\n  protocol: gemini-decisions\n"
	if err := ValidateV8SchemaBytes("config.yaml", []byte(good)); err != nil {
		t.Fatalf("schema refused protocol: %v", err)
	}
}

func TestValidateDecisionModelURL(t *testing.T) {
	for _, ok := range []string{"https://dm.example/v1/systemone", "http://127.0.0.1:8791/v1/systemone", "http://localhost:8791/x", "http://[::1]:8791/x"} {
		if err := ValidateDecisionModelURL(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"http://localhost.attacker.example/x", "http://192.168.1.5/x", "ftp://dm.example/x", "dm.example/x", "https://a:b@dm.example/x"} {
		if err := ValidateDecisionModelURL(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestDecisionModelKeyResolution(t *testing.T) {
	t.Setenv(DefenseClawDecisionModelKeyEnv, "  dm-token  ")
	t.Setenv("CUSTOM_DM_KEY", "custom-token")
	cfg := &Config{}
	if got := cfg.ResolvedDecisionModelKey(); got != "dm-token" {
		t.Fatalf("canonical key = %q", got)
	}
	cfg.DecisionModel.APIKeyEnv = "CUSTOM_DM_KEY"
	if got := cfg.ResolvedDecisionModelKey(); got != "custom-token" {
		t.Fatalf("custom key = %q", got)
	}
}

func TestDecisionModelRefusedInSecureClientV8(t *testing.T) {
	raw := "config_version: 8\ndeployment_mode: managed_enterprise\nenterprise:\n  profile: secure_client\ndecision_model:\n  enabled: false\n"
	_, err := ParseV8YAML("config.yaml", []byte(raw))
	if err == nil || !strings.Contains(err.Error(), "decision_model") {
		t.Fatalf("Secure Client v8 source with decision_model: err = %v", err)
	}
}

// A config written before decision_model.hook_connectors existed loads and
// saves unchanged: the list is empty, no connector gets cascade 2, and the
// key is not written back.
func TestDecisionModelHookConnectorsCompat(t *testing.T) {
	section := `decision_model:
  enabled: true
  model: openjev
  base_url: http://127.0.0.1:8791/v1/systemone
`
	cfg, err := LoadFromFile(writeDecisionModelConfig(t, 9, section))
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	if len(cfg.DecisionModel.HookConnectors) != 0 || cfg.DecisionModel.AnswersAlone("claudecode") {
		t.Fatalf("an existing config must keep the decision model in front of the judge only: %+v", cfg.DecisionModel)
	}
	out, err := yaml.Marshal(cfg.DecisionModel)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "hook_connectors") {
		t.Fatalf("an empty list must not be written: %s", out)
	}

	cfg, err = LoadFromFile(writeDecisionModelConfig(t, 9, section+"  hook_connectors: [ClaudeCode, codex]\n"))
	if err != nil {
		t.Fatalf("LoadFromFile with hook_connectors: %v", err)
	}
	d := cfg.DecisionModel
	if !d.AnswersAlone("claudecode") || !d.AnswersAlone("codex") || d.AnswersAlone("cursor") {
		t.Fatalf("hook_connectors = %v", d.HookConnectors)
	}
	d.HookConnectors = []string{"*"}
	if !d.AnswersAlone("cursor") {
		t.Fatal(`"*" must match every connector`)
	}
	d.Enabled = false
	if d.AnswersAlone("cursor") {
		t.Fatal("a disabled decision model must not answer alone")
	}
	d.Enabled, d.HookConnectors = true, []string{" ", "claude-code"}
	if err := d.Validate(); err != nil {
		t.Fatalf("a blank entry is ignored, as the CLI does: %v", err)
	}
	if !d.AnswersAlone("claudecode") || !d.AnswersAlone("Claude_Code") || d.AnswersAlone("") {
		t.Fatal("names must match in canonical form and a blank entry must match nothing")
	}
}

// The judge's connector gate matches names the way the decision model's list
// and the CLI do: "claude-code" in guardrail.judge.hook_connectors enables
// claudecode, so the CLI never reports cascade 3 where the gateway runs 2.
func TestJudgeHookConnectorEnabledMatchesCanonicalNames(t *testing.T) {
	j := JudgeConfig{Enabled: true, HookConnectors: []string{"claude-code", " ", "Codex"}}
	for _, name := range []string{"claudecode", "Claude_Code", "codex"} {
		if !j.HookConnectorEnabled(name) {
			t.Fatalf("%q must be enabled by %v", name, j.HookConnectors)
		}
	}
	if j.HookConnectorEnabled("") || j.HookConnectorEnabled("cursor") {
		t.Fatal("a blank or unlisted connector must not be enabled")
	}
}
