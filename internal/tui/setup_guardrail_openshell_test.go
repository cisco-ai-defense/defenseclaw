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
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// ------------------------------------------------------------------
// P2-#13 — Missing guardrail rows (host/model_name/original_model/
// api_base/retain_judge_bodies) + openshell tristate fields
// (sandbox_home, auto_pair, host_networking).
// ------------------------------------------------------------------

func TestApplyConfigField_GuardrailNewSurface(t *testing.T) {
	cases := []struct {
		key    string
		val    string
		verify func(c *config.Config) bool
	}{
		{"guardrail.host", "127.0.0.1", func(c *config.Config) bool { return c.Guardrail.Host == "127.0.0.1" }},
		{"guardrail.model_name", "gpt-4o-mini", func(c *config.Config) bool { return c.Guardrail.ModelName == "gpt-4o-mini" }},
		{"guardrail.original_model", "claude-sonnet", func(c *config.Config) bool { return c.Guardrail.OriginalModel == "claude-sonnet" }},
		{"guardrail.api_base", "https://proxy.example.com", func(c *config.Config) bool { return c.Guardrail.APIBase == "https://proxy.example.com" }},
		{"guardrail.retain_judge_bodies", "true", func(c *config.Config) bool { return c.Guardrail.RetainJudgeBodies }},
		{"guardrail.retain_judge_bodies_off", "false", func(c *config.Config) bool { return !c.Guardrail.RetainJudgeBodies }},
		// Hook fail mode round-trip: explicit "closed" persists.
		{"guardrail.hook_fail_mode", "closed", func(c *config.Config) bool { return c.Guardrail.HookFailMode == "closed" }},
		// Hook fail mode round-trip: explicit "open" persists.
		{"guardrail.hook_fail_mode_open", "open", func(c *config.Config) bool { return c.Guardrail.HookFailMode == "open" }},
		// Hook fail mode garbage normalizes to "open" — the form
		// MUST NEVER silently put the agent into a stricter posture
		// than the operator typed. Mirrors the same normalization
		// rule on both Python and Go config loaders.
		{"guardrail.hook_fail_mode_garbage", "klosed", func(c *config.Config) bool { return c.Guardrail.HookFailMode == "open" }},
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			c := &config.Config{}
			switch tc.key {
			case "guardrail.retain_judge_bodies_off":
				// Seed true, expect clear to false so boolVal
				// parsing actually flips the field.
				c.Guardrail.RetainJudgeBodies = true
				applyConfigField(c, "guardrail.retain_judge_bodies", tc.val)
			case "guardrail.hook_fail_mode_open", "guardrail.hook_fail_mode_garbage":
				// Same field, alternate value. The synthetic key
				// suffix lets us run multiple sub-cases against
				// hook_fail_mode without colliding in the table.
				applyConfigField(c, "guardrail.hook_fail_mode", tc.val)
			default:
				applyConfigField(c, tc.key, tc.val)
			}
			if !tc.verify(c) {
				t.Errorf("applyConfigField(%s=%s) didn't land", tc.key, tc.val)
			}
		})
	}
}

func TestSetupSections_GuardrailCoversNewRows(t *testing.T) {
	c := &config.Config{}
	p := NewSetupPanel(nil, c, nil)
	p.loadSections()
	var gr *configSection
	for i := range p.sections {
		if p.sections[i].Name == "Guardrail" {
			gr = &p.sections[i]
			break
		}
	}
	if gr == nil {
		t.Fatal("Guardrail section missing")
		return
	}
	want := []string{
		"guardrail.host",
		"guardrail.model_name",
		"guardrail.original_model",
		"guardrail.api_base",
		"guardrail.retain_judge_bodies",
		// hook_fail_mode must be visible in the Guardrail
		// section so operators can change response-layer hook
		// behavior without dropping to YAML. Forgetting to
		// surface it here is exactly what we shipped in 0.4.0
		// before this fix.
		"guardrail.hook_fail_mode",
	}
	have := map[string]bool{}
	for _, f := range gr.Fields {
		have[f.Key] = true
	}
	for _, k := range want {
		if !have[k] {
			t.Errorf("Guardrail section missing %s", k)
		}
	}
}

// TestParseTristateBool pins down all three states so a future
// refactor can't collapse them. The empty-string case is the one
// that matters most — collapsing nil and &false silently flips
// OpenShell defaults.
func TestParseTristateBool(t *testing.T) {
	t.Run("empty_is_nil", func(t *testing.T) {
		if p := parseTristateBool(""); p != nil {
			t.Errorf("empty should be nil, got %v", *p)
		}
	})
	t.Run("true", func(t *testing.T) {
		p := parseTristateBool("true")
		if p == nil || !*p {
			t.Errorf("parseTristateBool(true) = %v", p)
		}
	})
	t.Run("false", func(t *testing.T) {
		p := parseTristateBool("false")
		if p == nil || *p {
			t.Errorf("parseTristateBool(false) = %v", p)
		}
	})
	t.Run("uppercase_true", func(t *testing.T) {
		p := parseTristateBool("TRUE")
		if p == nil || !*p {
			t.Errorf("case-insensitive parse should accept TRUE, got %v", p)
		}
	})
	t.Run("malformed_clears", func(t *testing.T) {
		if p := parseTristateBool("lol"); p != nil {
			t.Errorf("malformed should clear (nil), got %v", *p)
		}
	})
}

func TestFmtTristateBool(t *testing.T) {
	if got := fmtTristateBool(nil); got != "" {
		t.Errorf("nil -> %q, want \"\"", got)
	}
	tru := true
	if got := fmtTristateBool(&tru); got != "true" {
		t.Errorf("&true -> %q", got)
	}
	fal := false
	if got := fmtTristateBool(&fal); got != "false" {
		t.Errorf("&false -> %q", got)
	}
}

func TestApplyConfigField_OpenShellTristates(t *testing.T) {
	t.Run("auto_pair_set_true", func(t *testing.T) {
		c := &config.Config{}
		applyConfigField(c, "openshell.auto_pair", "true")
		if c.OpenShell.AutoPair == nil || !*c.OpenShell.AutoPair {
			t.Errorf("auto_pair=true didn't set &true")
		}
	})
	t.Run("auto_pair_set_false", func(t *testing.T) {
		tru := true
		c := &config.Config{OpenShell: config.OpenShellConfig{AutoPair: &tru}}
		applyConfigField(c, "openshell.auto_pair", "false")
		if c.OpenShell.AutoPair == nil || *c.OpenShell.AutoPair {
			t.Errorf("auto_pair=false didn't land as &false")
		}
	})
	t.Run("auto_pair_clear_to_nil", func(t *testing.T) {
		fal := false
		c := &config.Config{OpenShell: config.OpenShellConfig{AutoPair: &fal}}
		applyConfigField(c, "openshell.auto_pair", "")
		if c.OpenShell.AutoPair != nil {
			t.Errorf("auto_pair=\"\" should clear to nil, got %v", *c.OpenShell.AutoPair)
		}
	})
	t.Run("host_networking_round_trip", func(t *testing.T) {
		c := &config.Config{}
		applyConfigField(c, "openshell.host_networking", "false")
		if c.OpenShell.HostNetworking == nil || *c.OpenShell.HostNetworking {
			t.Errorf("host_networking=false didn't land")
		}
		// ShouldHostNetworkingEnabled flips default to the
		// explicit value when set.
		if c.OpenShell.HostNetworkingEnabled() {
			t.Errorf("HostNetworkingEnabled should return false after explicit override")
		}
	})
	t.Run("sandbox_home", func(t *testing.T) {
		c := &config.Config{}
		applyConfigField(c, "openshell.sandbox_home", "/var/lib/dc-sbx")
		if c.OpenShell.SandboxHome != "/var/lib/dc-sbx" {
			t.Errorf("sandbox_home not applied: %q", c.OpenShell.SandboxHome)
		}
	})
}

func TestSetupSections_OpenShellHasTristates(t *testing.T) {
	c := &config.Config{}
	p := NewSetupPanel(nil, c, nil)
	p.loadSections()
	var os *configSection
	for i := range p.sections {
		if p.sections[i].Name == "OpenShell" {
			os = &p.sections[i]
			break
		}
	}
	if os == nil {
		t.Fatal("OpenShell section missing")
		return
	}
	// Each tristate must be a kind=choice with exactly the three
	// options "", "true", "false"; anything else means the edit
	// path can't preserve the default-vs-explicit distinction.
	seenAutoPair, seenHostNet, seenSandboxHome := false, false, false
	for _, f := range os.Fields {
		switch f.Key {
		case "openshell.auto_pair":
			seenAutoPair = true
			if f.Kind != "choice" {
				t.Errorf("auto_pair Kind=%q, want choice", f.Kind)
			}
			if len(f.Options) != 3 || f.Options[0] != "" || f.Options[1] != "true" || f.Options[2] != "false" {
				t.Errorf("auto_pair Options=%v, want ['', true, false]", f.Options)
			}
		case "openshell.host_networking":
			seenHostNet = true
			if f.Kind != "choice" {
				t.Errorf("host_networking Kind=%q, want choice", f.Kind)
			}
		case "openshell.sandbox_home":
			seenSandboxHome = true
		}
	}
	if !seenAutoPair {
		t.Error("openshell.auto_pair not in section")
	}
	if !seenHostNet {
		t.Error("openshell.host_networking not in section")
	}
	if !seenSandboxHome {
		t.Error("openshell.sandbox_home not in section")
	}
}
