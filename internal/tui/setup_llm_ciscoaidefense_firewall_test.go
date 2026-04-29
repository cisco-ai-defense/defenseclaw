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
// P2-#12 — Unified LLM editor, Cisco AI Defense editor, Firewall
// read-only.
//
// Originally this covered the v4 inspect_llm: block; with the v5
// migration the editable surface now lives under the top-level llm:
// block (consumed by guardrail, MCP scanner, skill scanner, and
// plugin scanner via Config.ResolveLLM). The legacy inspect_llm:
// section is still rendered by the TUI but is read-only — writes are
// routed through the applyConfigField llm.* keys and migrated on
// load, so editing inspect_llm: directly would drift from the
// resolver.
// ------------------------------------------------------------------

// TestApplyConfigField_UnifiedLLMFullSurface covers the editable
// surface of the unified llm: block. These are the keys the TUI
// actually dispatches when the operator edits the "Unified LLM"
// section; they must land on c.LLM so Config.ResolveLLM picks them
// up.
func TestApplyConfigField_UnifiedLLMFullSurface(t *testing.T) {
	cases := []struct {
		key    string
		val    string
		verify func(c *config.Config) bool
	}{
		{"llm.provider", "anthropic", func(c *config.Config) bool { return c.LLM.Provider == "anthropic" }},
		{"llm.model", "claude-3-5-sonnet-20241022", func(c *config.Config) bool { return c.LLM.Model == "claude-3-5-sonnet-20241022" }},
		{"llm.api_key", "sk-fake", func(c *config.Config) bool { return c.LLM.APIKey == "sk-fake" }},
		{"llm.api_key_env", "DEFENSECLAW_LLM_KEY", func(c *config.Config) bool { return c.LLM.APIKeyEnv == "DEFENSECLAW_LLM_KEY" }},
		{"llm.base_url", "https://api.example.com", func(c *config.Config) bool { return c.LLM.BaseURL == "https://api.example.com" }},
		{"llm.timeout", "30", func(c *config.Config) bool { return c.LLM.Timeout == 30 }},
		{"llm.max_retries", "5", func(c *config.Config) bool { return c.LLM.MaxRetries == 5 }},
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

// TestApplyConfigField_LegacyInspectLLMStillWrites keeps the v4 path
// alive during the migration window so older TUI snapshots (and any
// `defenseclaw config set inspect_llm.* ...` muscle memory) still
// work. The config.load() shim copies these into c.LLM, but the
// setter itself must continue to populate c.InspectLLM for the
// round-trip to succeed.
func TestApplyConfigField_LegacyInspectLLMStillWrites(t *testing.T) {
	c := &config.Config{}
	applyConfigField(c, "inspect_llm.provider", "openai")
	applyConfigField(c, "inspect_llm.model", "gpt-4o")
	if c.InspectLLM.Provider != "openai" || c.InspectLLM.Model != "gpt-4o" {
		t.Fatalf("legacy inspect_llm writes dropped: provider=%q model=%q", c.InspectLLM.Provider, c.InspectLLM.Model)
	}
}

// TestSetupSections_UnifiedLLMEditable guards the shape of the
// Unified LLM section: all rows must be editable kinds (not header)
// so the operator can actually change them. The api_key must be
// kind=password so the value is masked in View.
func TestSetupSections_UnifiedLLMEditable(t *testing.T) {
	c := &config.Config{}
	p := NewSetupPanel(nil, c, nil)
	p.loadSections()
	// The unified llm.* fields live on the "General" section header
	// under the "── Unified LLM ──" divider. Scan every section and
	// collect the rows whose Key has the llm. prefix — this mirrors
	// what the TUI actually dispatches to applyConfigField.
	requiredEditableKeys := map[string]bool{
		"llm.provider":    false,
		"llm.model":       false,
		"llm.api_key":     false,
		"llm.api_key_env": false,
		"llm.base_url":    false,
		"llm.timeout":     false,
		"llm.max_retries": false,
	}
	var apiKeyKind string
	for si := range p.sections {
		for _, f := range p.sections[si].Fields {
			if _, ok := requiredEditableKeys[f.Key]; !ok {
				continue
			}
			if f.Kind == "header" {
				t.Errorf("%s must be editable, got kind=header (section=%s)", f.Key, p.sections[si].Name)
			}
			requiredEditableKeys[f.Key] = true
			if f.Key == "llm.api_key" {
				apiKeyKind = f.Kind
			}
		}
	}
	for k, seen := range requiredEditableKeys {
		if !seen {
			t.Errorf("Unified LLM section missing editable key %q", k)
		}
	}
	if apiKeyKind != "password" {
		t.Errorf("llm.api_key Kind=%q, want password", apiKeyKind)
	}
}

// TestSetupSections_CiscoAIDefenseEditable verifies the section is
// present and exposes the endpoint/key/rule fields operators need for
// first-run remote/both scanner setup. api_key must be Kind=password so
// the renderer masks it.
func TestSetupSections_CiscoAIDefenseEditable(t *testing.T) {
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
		return
	}
	want := map[string]string{
		"cisco_ai_defense.endpoint":      "string",
		"cisco_ai_defense.api_key":       "password",
		"cisco_ai_defense.api_key_env":   "string",
		"cisco_ai_defense.timeout_ms":    "int",
		"cisco_ai_defense.enabled_rules": "string",
	}
	seen := map[string]bool{}
	for _, f := range cisco.Fields {
		if kind, ok := want[f.Key]; ok {
			seen[f.Key] = true
			if f.Kind != kind {
				t.Errorf("%s Kind=%q, want %q", f.Key, f.Kind, kind)
			}
			if f.Hint == "" {
				t.Errorf("%s missing Hint", f.Key)
			}
		}
	}
	for key := range want {
		if !seen[key] {
			t.Errorf("Cisco AI Defense section missing key %q", key)
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

// TestSetupSections_CiscoAIDefenseAPIKeyUsesPasswordKind keeps the
// masking contract close to the section helper. The field may hold the
// raw value internally for editing; the render path masks all
// Kind=password fields.
func TestSetupSections_CiscoAIDefenseAPIKeyUsesPasswordKind(t *testing.T) {
	c := &config.Config{CiscoAIDefense: config.CiscoAIDefenseConfig{APIKey: "secret"}}
	fields := ciscoAIDefenseFields(c)
	var apiKey configField
	for _, f := range fields {
		if f.Key == "cisco_ai_defense.api_key" {
			apiKey = f
			break
		}
	}
	if apiKey.Kind != "password" {
		t.Fatalf("api_key Kind=%q, want password", apiKey.Kind)
	}
	if apiKey.Value != "secret" {
		t.Fatalf("api_key Value should keep editable raw value, got %q", apiKey.Value)
	}
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
		return
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

// TestApplyConfigField_CiscoAIDefenseWrites verifies the TUI config
// editor can now update the full Cisco AI Defense block.
func TestApplyConfigField_CiscoAIDefenseWrites(t *testing.T) {
	c := &config.Config{}
	applyConfigField(c, "cisco_ai_defense.endpoint", "https://example.test")
	applyConfigField(c, "cisco_ai_defense.api_key", "new-secret")
	applyConfigField(c, "cisco_ai_defense.api_key_env", "CISCO_TEST_KEY")
	applyConfigField(c, "cisco_ai_defense.timeout_ms", "4500")
	applyConfigField(c, "cisco_ai_defense.enabled_rules", "pii,exfil")
	if c.CiscoAIDefense.Endpoint != "https://example.test" ||
		c.CiscoAIDefense.APIKey != "new-secret" ||
		c.CiscoAIDefense.APIKeyEnv != "CISCO_TEST_KEY" ||
		c.CiscoAIDefense.TimeoutMs != 4500 ||
		strings.Join(c.CiscoAIDefense.EnabledRules, ",") != "pii,exfil" {
		t.Fatalf("Cisco AI Defense edits did not land: %+v", c.CiscoAIDefense)
	}

	// Firewall is still deliberately read-only.
	applyConfigField(c, "firewall.config_file", "/tmp/evil.conf")
	if c.Firewall.ConfigFile != "" {
		t.Errorf("applyConfigField should never mutate firewall paths, got %q", c.Firewall.ConfigFile)
	}
}
