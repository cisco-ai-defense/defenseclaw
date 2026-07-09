// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validAgentControlConfig() AgentControlConfig {
	return AgentControlConfig{
		Enabled:             true,
		Deployment:          "self_hosted",
		ServerURL:           "https://agent-control.example.test",
		InstallationID:      "installation-1",
		APIKeyEnv:           "AGENT_CONTROL_API_KEY",
		AgentName:           "defenseclaw-policy-sync",
		TargetType:          "defenseclaw.installation",
		RefreshSeconds:      60,
		CachePollSeconds:    2,
		InitRetryMaxSeconds: 300,
		OPA: AgentControlOPAConfig{
			Enabled:    true,
			Precedence: "stricter",
			Activation: "reload",
		},
		RulePack: AgentControlRulePackConfig{
			Activation: "restart",
			MaxRules:   1000,
		},
		Observability: AgentControlObservabilityConfig{Enabled: true, IncludeContent: true},
	}
}

func TestLoadAgentControlRegexSourceSchema(t *testing.T) {
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	data := []byte(`guardrail:
  regex_source: agent_control
agent_control:
  enabled: true
  deployment: self_hosted
  server_url: https://agent-control.example.test
  installation_id: defenseclaw-laptop-01
  api_key_env: AGENT_CONTROL_API_KEY
  rule_pack:
    enabled: true
`)
	if err := os.WriteFile(filepath.Join(home, DefaultConfigName), data, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Guardrail.EffectiveRegexSource() != RegexSourceAgentControl {
		t.Fatalf("regex source = %q", cfg.Guardrail.EffectiveRegexSource())
	}
	if cfg.AgentControl.Deployment != "self_hosted" ||
		cfg.AgentControl.ServerURL != "https://agent-control.example.test" ||
		cfg.AgentControl.InstallationID != "defenseclaw-laptop-01" ||
		cfg.AgentControl.APIKeyEnv != "AGENT_CONTROL_API_KEY" {
		t.Fatalf("Agent Control config = %+v", cfg.AgentControl)
	}
}

func TestLoadRejectsContradictoryRegexSourceAndManagedRuleLane(t *testing.T) {
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	data := []byte(`guardrail:
  regex_source: local
agent_control:
  enabled: true
  deployment: self_hosted
  server_url: https://agent-control.example.test
  installation_id: defenseclaw-laptop-01
  api_key_env: AGENT_CONTROL_API_KEY
  rule_pack:
    enabled: true
`)
	if err := os.WriteFile(filepath.Join(home, DefaultConfigName), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "regex_source=local") {
		t.Fatalf("Load error = %v", err)
	}
}

func TestAgentControlConfigValidate(t *testing.T) {
	cfg := validAgentControlConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*AgentControlConfig){
		"bad deployment":        func(c *AgentControlConfig) { c.Deployment = "other" },
		"missing server URL":    func(c *AgentControlConfig) { c.ServerURL = "" },
		"missing installation":  func(c *AgentControlConfig) { c.InstallationID = "" },
		"missing API key env":   func(c *AgentControlConfig) { c.APIKeyEnv = "" },
		"bad agent name":        func(c *AgentControlConfig) { c.AgentName = "shared-application-agent" },
		"bad target type":       func(c *AgentControlConfig) { c.TargetType = "application" },
		"bad precedence":        func(c *AgentControlConfig) { c.OPA.Precedence = "merge" },
		"bad OPA activation":    func(c *AgentControlConfig) { c.OPA.Activation = "restart" },
		"bad rule activation":   func(c *AgentControlConfig) { c.RulePack.Activation = "reload" },
		"bad max rules":         func(c *AgentControlConfig) { c.RulePack.MaxRules = 1001 },
		"bad refresh":           func(c *AgentControlConfig) { c.RefreshSeconds = 0 },
		"bad cache poll":        func(c *AgentControlConfig) { c.CachePollSeconds = 0 },
		"bad init retry":        func(c *AgentControlConfig) { c.InitRetryMaxSeconds = 0 },
		"overlong installation": func(c *AgentControlConfig) { c.InstallationID = strings.Repeat("x", 256) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			value := validAgentControlConfig()
			mutate(&value)
			if err := value.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestDefaultAgentControlConfig(t *testing.T) {
	cfg := DefaultConfig().AgentControl
	if cfg.Enabled {
		t.Fatal("Agent Control integration must remain opt-in")
	}
	if !cfg.Observability.Enabled || !cfg.Observability.IncludeContent {
		t.Fatalf("Agent Control observability defaults = %+v, want enabled exact content", cfg.Observability)
	}
	if cfg.OPA.Enabled {
		t.Fatal("Agent Control OPA threshold management must remain opt-in")
	}
	if cfg.Deployment != "cisco_cloud" || cfg.APIKeyEnv != "AGENT_CONTROL_API_KEY" {
		t.Fatalf("Agent Control setup defaults = %+v", cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default Agent Control config is invalid: %v", err)
	}
}

func TestGuardrailRegexSourceValidation(t *testing.T) {
	for _, source := range []string{RegexSourceLocal, RegexSourceAgentControl, RegexSourceHybrid} {
		cfg := GuardrailConfig{RegexSource: source}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("source %q: %v", source, err)
		}
	}
	if err := (&GuardrailConfig{RegexSource: "remote"}).Validate(); err == nil {
		t.Fatal("expected invalid regex source error")
	}
	if got := (&GuardrailConfig{}).EffectiveRegexSource(); got != RegexSourceLocal {
		t.Fatalf("zero-value source = %q, want local", got)
	}
}

func TestGuardrailConfigRejectsDuplicateOverlayDirs(t *testing.T) {
	cfg := GuardrailConfig{RulePackOverlayDirs: []string{"/tmp/rules", "/tmp/rules/"}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected duplicate overlay error")
	}
}
