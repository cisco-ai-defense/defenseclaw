// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
			d.EffectiveAPIKeyEnv() != DefenseClawDecisionModelKeyEnv {
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
