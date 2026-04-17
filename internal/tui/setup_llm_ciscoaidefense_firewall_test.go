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

package tui

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// ------------------------------------------------------------------
// P2-#12 — Inspect LLM editor, Cisco AI Defense read-only, Firewall
// read-only.
// ------------------------------------------------------------------

func TestApplyConfigField_InspectLLMFullSurface(t *testing.T) {
	cases := []struct {
		key    string
		val    string
		verify func(c *config.Config) bool
	}{
		{"inspect_llm.provider", "anthropic", func(c *config.Config) bool { return c.InspectLLM.Provider == "anthropic" }},
		{"inspect_llm.model", "claude-opus", func(c *config.Config) bool { return c.InspectLLM.Model == "claude-opus" }},
		{"inspect_llm.api_key", "sk-fake", func(c *config.Config) bool { return c.InspectLLM.APIKey == "sk-fake" }},
		{"inspect_llm.api_key_env", "ANTHROPIC_API_KEY", func(c *config.Config) bool { return c.InspectLLM.APIKeyEnv == "ANTHROPIC_API_KEY" }},
		{"inspect_llm.base_url", "https://api.example.com", func(c *config.Config) bool { return c.InspectLLM.BaseURL == "https://api.example.com" }},
		{"inspect_llm.timeout", "30", func(c *config.Config) bool { return c.InspectLLM.Timeout == 30 }},
		{"inspect_llm.max_retries", "5", func(c *config.Config) bool { return c.InspectLLM.MaxRetries == 5 }},
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			c := &config.Config{}
			applyConfigField(c, tc.key, tc.val)
			if !tc.verify(c) {
				t.Errorf("applyConfigField(%s=%s) didn't land", tc.key, tc.val)
			}
		})
	}
}

// TestSetupSections_InspectLLMEditable guards the shape of the
// Inspect LLM section: all rows must be editable kinds (not header)
// so the operator can actually change them. The api_key must be
// kind=password so the value is masked in View.
func TestSetupSections_InspectLLMEditable(t *testing.T) {
	c := &config.Config{}
	p := NewSetupPanel(nil, c, nil)
	p.loadSections()
	var llm *configSection
	for i := range p.sections {
		if p.sections[i].Name == "Inspect LLM" {
			llm = &p.sections[i]
			break
		}
	}
	if llm == nil {
		t.Fatal("Inspect LLM section missing")
	}
	requiredEditableKeys := map[string]bool{
		"inspect_llm.provider":    false,
		"inspect_llm.model":       false,
		"inspect_llm.api_key":     false,
		"inspect_llm.api_key_env": false,
		"inspect_llm.base_url":    false,
		"inspect_llm.timeout":     false,
		"inspect_llm.max_retries": false,
	}
	for _, f := range llm.Fields {
		if _, ok := requiredEditableKeys[f.Key]; !ok {
			continue
		}
		if f.Kind == "header" {
			t.Errorf("%s must be editable, got kind=header", f.Key)
		}
		requiredEditableKeys[f.Key] = true
	}
	for k, seen := range requiredEditableKeys {
		if !seen {
			t.Errorf("Inspect LLM section missing editable key %q", k)
		}
	}
	// API key must be masked kind.
	for _, f := range llm.Fields {
		if f.Key == "inspect_llm.api_key" && f.Kind != "password" {
			t.Errorf("inspect_llm.api_key Kind=%q, want password", f.Kind)
		}
	}
}

// TestSetupSections_CiscoAIDefenseReadOnly verifies the section is
// present and every row is kind=header so the config form's Enter
// binding never enters edit mode. This is the whole point of the
// read-only designation.
func TestSetupSections_CiscoAIDefenseReadOnly(t *testing.T) {
	c := &config.Config{
		CiscoAIDefense: config.CiscoAIDefenseConfig{
			Endpoint:     "https://us.api.inspect.aidefense.security.cisco.com",
			APIKeyEnv:    "CISCO_AI_DEFENSE_API_KEY",
			TimeoutMs:    3000,
			EnabledRules: []string{"pii", "toxicity"},
		},
	}
	p := NewSetupPanel(nil, c, nil)
	p.loadSections()
	var cisco *configSection
	for i := range p.sections {
		if p.sections[i].Name == "Cisco AI Defense" {
			cisco = &p.sections[i]
			break
		}
	}
	if cisco == nil {
		t.Fatal("Cisco AI Defense section missing")
	}
	for _, f := range cisco.Fields {
		if f.Kind != "header" {
			t.Errorf("%s must be read-only, got kind=%q", f.Key, f.Kind)
		}
	}
	// The rules summary must include both entries so operators can
	// see the provisioned allow-list at a glance.
	var rulesRow configField
	for _, f := range cisco.Fields {
		if f.Key == "cisco_ai_defense.enabled_rules" {
			rulesRow = f
			break
		}
	}
	if !strings.Contains(rulesRow.Value, "pii") || !strings.Contains(rulesRow.Value, "toxicity") {
		t.Errorf("enabled_rules summary: %q", rulesRow.Value)
	}
}

// TestSetupSections_CiscoAIDefenseAPIKeyStates exercises the three
// API-key states the operator cares about: inline, env-resolved, and
// unset. Each must render a distinct, non-leaking summary string.
func TestSetupSections_CiscoAIDefenseAPIKeyStates(t *testing.T) {
	t.Run("inline_redacted", func(t *testing.T) {
		c := &config.Config{CiscoAIDefense: config.CiscoAIDefenseConfig{APIKey: "secret"}}
		fields := ciscoAIDefenseFields(c)
		var v string
		for _, f := range fields {
			if f.Key == "cisco_ai_defense.api_key" {
				v = f.Value
			}
		}
		if strings.Contains(v, "secret") {
			t.Errorf("api_key row leaked the cleartext: %q", v)
		}
		if !strings.Contains(v, "redacted") {
			t.Errorf("expected redacted marker, got %q", v)
		}
	})
	t.Run("env_unresolved", func(t *testing.T) {
		t.Setenv("UNIT_TEST_UNSET_KEY_CAD", "")
		c := &config.Config{CiscoAIDefense: config.CiscoAIDefenseConfig{APIKeyEnv: "UNIT_TEST_UNSET_KEY_CAD"}}
		fields := ciscoAIDefenseFields(c)
		var v string
		for _, f := range fields {
			if f.Key == "cisco_ai_defense.api_key" {
				v = f.Value
			}
		}
		if !strings.Contains(v, "UNIT_TEST_UNSET_KEY_CAD") {
			t.Errorf("missing env var name: %q", v)
		}
		if !strings.Contains(v, "not set") {
			t.Errorf("env_unresolved should advertise 'not set', got %q", v)
		}
	})
	t.Run("unset", func(t *testing.T) {
		c := &config.Config{}
		fields := ciscoAIDefenseFields(c)
		var v string
		for _, f := range fields {
			if f.Key == "cisco_ai_defense.api_key" {
				v = f.Value
			}
		}
		if v != "(unset)" {
			t.Errorf("unset expected '(unset)', got %q", v)
		}
	})
}

// TestSetupSections_FirewallReadOnly mirrors the CiscoAIDefense test
// for the Firewall anchor rows. The "How to edit" hint must point to
// config.yaml so operators don't spend minutes hunting for an edit
// binding that doesn't exist.
func TestSetupSections_FirewallReadOnly(t *testing.T) {
	c := &config.Config{
		Firewall: config.FirewallConfig{
			ConfigFile: "/etc/pf.conf",
			RulesFile:  "/etc/pf.anchors/defenseclaw",
			AnchorName: "defenseclaw",
		},
	}
	p := NewSetupPanel(nil, c, nil)
	p.loadSections()
	var fw *configSection
	for i := range p.sections {
		if p.sections[i].Name == "Firewall" {
			fw = &p.sections[i]
			break
		}
	}
	if fw == nil {
		t.Fatal("Firewall section missing")
	}
	for _, f := range fw.Fields {
		if f.Kind != "header" {
			t.Errorf("%s must be read-only, got kind=%q", f.Key, f.Kind)
		}
	}
	var hint string
	for _, f := range fw.Fields {
		if f.Key == "firewall.hint" {
			hint = f.Value
		}
	}
	if !strings.Contains(hint, "config.yaml") {
		t.Errorf("hint doesn't mention config.yaml: %q", hint)
	}
}

// TestApplyConfigField_CiscoAIDefenseNoOp reinforces that applying a
// cisco_ai_defense.* key silently no-ops (the switch falls through
// and actions-matrix prefix doesn't match). This prevents a future
// refactor from accidentally adding an edit path.
func TestApplyConfigField_CiscoAIDefenseNoOp(t *testing.T) {
	c := &config.Config{}
	applyConfigField(c, "cisco_ai_defense.api_key", "attacker-set-secret")
	if c.CiscoAIDefense.APIKey != "" {
		t.Errorf("applyConfigField should never mutate cisco_ai_defense.api_key, got %q", c.CiscoAIDefense.APIKey)
	}
	applyConfigField(c, "firewall.config_file", "/tmp/evil.conf")
	if c.Firewall.ConfigFile != "" {
		t.Errorf("applyConfigField should never mutate firewall paths, got %q", c.Firewall.ConfigFile)
	}
}
