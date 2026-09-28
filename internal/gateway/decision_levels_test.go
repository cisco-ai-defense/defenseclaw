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

package gateway

import (
	"maps"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

const (
	levelsStrictPack     = "/tmp/policies/guardrail/strict"
	levelsPermissivePack = "/tmp/policies/guardrail/permissive"
)

// TestGuardrailLevelThresholds pins the block/alert ranks hook tool-call
// decisions use (guardrailToolCallThresholdsForConfigConnector): the
// connector's block_at / alert_at, else the global value, else the connector's
// rule-pack profile, then the alert rank clamped to the block rank. Ranks:
// CRITICAL=4 HIGH=3 MEDIUM=2 LOW=1.
func TestGuardrailLevelThresholds(t *testing.T) {
	strictCodexCritical := func(c *config.Config) {
		c.Guardrail.RulePackDir = levelsStrictPack
		c.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
			"codex": {BlockAt: "CRITICAL"},
		}
	}
	tests := []struct {
		name      string
		edit      func(*config.Config)
		connector string
		wantBlock int
		wantAlert int
	}{
		{"default pack, no levels", nil, "codex", severityCritical, severityMedium},
		{"strict pack, no levels", func(c *config.Config) {
			c.Guardrail.RulePackDir = levelsStrictPack
		}, "codex", severityMedium, severityLow},
		{"permissive pack, no levels", func(c *config.Config) {
			c.Guardrail.RulePackDir = levelsPermissivePack
		}, "codex", severityCritical, severityHigh},
		{"default pack + global block_at HIGH", func(c *config.Config) {
			c.Guardrail.BlockAt = "HIGH"
		}, "codex", severityHigh, severityMedium},
		{"strict pack + connector block_at CRITICAL", strictCodexCritical, "codex", severityCritical, severityLow},
		{"strict pack, connector without a level", strictCodexCritical, "claudecode", severityMedium, severityLow},
		{"connector level beats global", func(c *config.Config) {
			c.Guardrail.BlockAt = "HIGH"
			c.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
				"codex": {BlockAt: "MEDIUM"},
			}
		}, "codex", severityMedium, severityMedium},
		{"global level beats the connector's own pack", func(c *config.Config) {
			c.Guardrail.BlockAt = "CRITICAL"
			c.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
				"codex": {RulePackDir: levelsStrictPack},
			}
		}, "codex", severityCritical, severityLow},
		{"alert clamped to block_at LOW", func(c *config.Config) {
			c.Guardrail.BlockAt = "LOW"
		}, "codex", severityLow, severityLow},
		{"alert_at above the block level is clamped", func(c *config.Config) {
			c.Guardrail.RulePackDir = levelsStrictPack
			c.Guardrail.AlertAt = "HIGH"
		}, "codex", severityMedium, severityMedium},
		{"alert_at alone", func(c *config.Config) {
			c.Guardrail.AlertAt = "LOW"
		}, "codex", severityCritical, severityLow},
		{"any case and spacing", func(c *config.Config) {
			c.Guardrail.BlockAt = " high "
			c.Guardrail.AlertAt = "low"
		}, "codex", severityHigh, severityLow},
		{"invalid level keeps the pack's", func(c *config.Config) {
			c.Guardrail.BlockAt = "SEVERE" // only reachable by skipping Validate
		}, "codex", severityCritical, severityMedium},
		{"empty connector resolves the global level", func(c *config.Config) {
			c.Guardrail.BlockAt = "HIGH"
			c.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
				"codex": {BlockAt: "LOW"},
			}
		}, "", severityHigh, severityMedium},
		// An automatically protected connector keeps its overlay pack; the
		// global level applies on top of it.
		{"auto-protected connector: overlay pack + global level", func(c *config.Config) {
			c.ApplicationProtection.Enabled = true
			c.ApplicationProtection.Guardrail.RulePackDir = levelsStrictPack
			c.Guardrail.BlockAt = "HIGH"
		}, "cursor", severityHigh, severityLow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{}
			if tt.edit != nil {
				tt.edit(cfg)
			}
			block, alert := guardrailToolCallThresholdsForConfigConnector(cfg, tt.connector)
			if block != tt.wantBlock || alert != tt.wantAlert {
				t.Fatalf("thresholds(%q) = block %d / alert %d, want %d / %d",
					tt.connector, block, alert, tt.wantBlock, tt.wantAlert)
			}
		})
	}

	if block, alert := guardrailToolCallThresholdsForConfigConnector(nil, "codex"); block != severityCritical || alert != severityMedium {
		t.Fatalf("nil config thresholds = %d / %d, want the default pack's", block, alert)
	}
}

// TestGuardrailLevelThresholdsForGuardrailConfig covers the bare
// GuardrailConfig variant, which the guardrail proxy's tool-call inspection
// resolves with no connector (the global scope).
func TestGuardrailLevelThresholdsForGuardrailConfig(t *testing.T) {
	tests := []struct {
		name      string
		gc        *config.GuardrailConfig
		connector string
		wantBlock int
		wantAlert int
	}{
		{"nil config", nil, "", severityCritical, severityMedium},
		{"no levels", &config.GuardrailConfig{}, "", severityCritical, severityMedium},
		{"global block_at HIGH", &config.GuardrailConfig{BlockAt: "HIGH"}, "", severityHigh, severityMedium},
		{"strict pack + alert_at clamped", &config.GuardrailConfig{
			RulePackDir: levelsStrictPack, AlertAt: "HIGH",
		}, "", severityMedium, severityMedium},
		{"connector override", &config.GuardrailConfig{
			BlockAt:    "HIGH",
			Connectors: map[string]config.PerConnectorGuardrailConfig{"codex": {BlockAt: "LOW"}},
		}, "codex", severityLow, severityLow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			block, alert := guardrailToolCallThresholdsForConnector(tt.gc, tt.connector)
			if block != tt.wantBlock || alert != tt.wantAlert {
				t.Fatalf("thresholds(%q) = block %d / alert %d, want %d / %d",
					tt.connector, block, alert, tt.wantBlock, tt.wantAlert)
			}
		})
	}
}

// TestGuardrailLevelActions checks the resulting tool-call severity → action
// mapping on the hook lane and the proxy lane, that blocking still comes
// before human approval, and that prompts, completions and other content keep
// the rule pack's levels.
func TestGuardrailLevelActions(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.BlockAt = "HIGH" // default pack otherwise blocks CRITICAL only
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"codex":      {RulePackDir: levelsStrictPack, BlockAt: "CRITICAL"},
		"claudecode": {AlertAt: "CRITICAL"}, // clamped to its block level, HIGH
	}
	for _, c := range []struct{ connector, severity, want string }{
		{"opencode", "CRITICAL", guardrailActionBlock},
		{"opencode", "HIGH", guardrailActionBlock},
		{"opencode", "MEDIUM", guardrailActionAlert},
		{"opencode", "LOW", guardrailActionAllow},
		{"codex", "CRITICAL", guardrailActionBlock},
		{"codex", "HIGH", guardrailActionAlert},
		{"codex", "LOW", guardrailActionAlert},
		{"claudecode", "HIGH", guardrailActionBlock},
		{"claudecode", "MEDIUM", guardrailActionAllow},
	} {
		if got := guardrailToolCallActionForConnector(cfg, c.connector, c.severity, true); got != c.want {
			t.Errorf("%s %s = %q, want %q", c.connector, c.severity, got, c.want)
		}
	}
	// Content decisions ignore the levels: the default pack alerts on HIGH.
	if got := guardrailRuntimeActionForConnector(cfg, "opencode", "HIGH", true); got != guardrailActionAlert {
		t.Errorf("content HIGH with block_at HIGH = %q, want alert (the pack's level)", got)
	}
	high := []RuleFinding{{RuleID: "levels-content", Severity: "HIGH"}}
	if got := buildVerdictWithConfig(high, "completion", cfg, false).Action; got != guardrailActionAlert {
		t.Errorf("completion verdict with block_at HIGH = %q, want alert", got)
	}

	hilt := &config.Config{}
	hilt.Guardrail.HILT = config.HILTConfig{Enabled: true, MinSeverity: "HIGH"}
	hilt.Guardrail.BlockAt = "HIGH"
	if got := guardrailToolCallActionForConnector(hilt, "codex", "HIGH", true); got != guardrailActionBlock {
		t.Errorf("block_at HIGH + HILT HIGH: HIGH = %q, want block (blocking precedes approval)", got)
	}
	hilt.Guardrail.BlockAt = "CRITICAL"
	if got := guardrailToolCallActionForConnector(hilt, "codex", "HIGH", true); got != guardrailActionConfirm {
		t.Errorf("block_at CRITICAL + HILT HIGH: HIGH = %q, want confirm", got)
	}

	proxy := &config.GuardrailConfig{BlockAt: "MEDIUM"}
	if got := guardrailToolCallActionForGuardrailConnector(proxy, "", "MEDIUM", false); got != guardrailActionBlock {
		t.Errorf("proxy tool call block_at MEDIUM: MEDIUM = %q, want block", got)
	}
	if got := guardrailToolCallActionForGuardrailConnector(proxy, "", "LOW", false); got != guardrailActionAllow {
		t.Errorf("proxy tool call block_at MEDIUM: LOW = %q, want allow", got)
	}
	if got := guardrailRuntimeActionForGuardrail(proxy, "MEDIUM", false); got != guardrailActionAlert {
		t.Errorf("proxy prompt block_at MEDIUM: MEDIUM = %q, want alert (the pack's level)", got)
	}
}

// TestGuardrailLevelsNeverReleaseCritical extends the CRITICAL-always-blocks
// invariant (profile_action_matrix_test.go) to every level combination: no
// block_at / alert_at value can make a CRITICAL finding anything but a block,
// even with human approval armed at CRITICAL.
func TestGuardrailLevelsNeverReleaseCritical(t *testing.T) {
	for _, pack := range []string{"", levelsStrictPack, levelsPermissivePack} {
		for _, blockAt := range []string{"", "CRITICAL", "HIGH", "MEDIUM", "LOW", "critical", "bogus"} {
			for _, alertAt := range []string{"", "CRITICAL", "LOW"} {
				cfg := &config.Config{}
				cfg.Guardrail.RulePackDir = pack
				cfg.Guardrail.BlockAt = blockAt
				cfg.Guardrail.AlertAt = alertAt
				cfg.Guardrail.HILT = config.HILTConfig{Enabled: true, MinSeverity: "CRITICAL"}
				if got := guardrailToolCallActionForConnector(cfg, "codex", "CRITICAL", true); got != guardrailActionBlock {
					t.Errorf("pack=%q block_at=%q alert_at=%q: CRITICAL = %q, want block", pack, blockAt, alertAt, got)
				}
			}
		}
	}
}

// TestGuardrailLevelsReloadClassification pins the reload contract: hook
// tool-call decisions read the start-time config, so a global block_at /
// alert_at change restarts the guardrail (a hot reload is refused), and a
// per-connector one is inside guardrail.connectors and restarts like any
// other per-connector change.
func TestGuardrailLevelsReloadClassification(t *testing.T) {
	base := &config.Config{}
	base.Guardrail.Enabled = true
	base.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{"codex": {}}
	pair := func(edit func(*config.Config)) (*config.Config, *config.Config) {
		newCfg := *base
		newCfg.Guardrail.Connectors = maps.Clone(base.Guardrail.Connectors)
		edit(&newCfg)
		return base, &newCfg
	}

	for name, edit := range map[string]func(*config.Config){
		"global block_at": func(c *config.Config) { c.Guardrail.BlockAt = "HIGH" },
		"global alert_at": func(c *config.Config) { c.Guardrail.AlertAt = "LOW" },
	} {
		oldCfg, newCfg := pair(edit)
		if !guardrailNeedsRestart(oldCfg, newCfg) {
			t.Errorf("%s: guardrailNeedsRestart = false, want true", name)
		}
		if diff := diffConfigs(oldCfg, newCfg); !slices.Contains(diff.RestartRequired, "guardrail") {
			t.Errorf("%s: diff = %+v, want guardrail to require a restart", name, diff)
		}
	}

	for name, edit := range map[string]func(*config.Config){
		"connector block_at": func(c *config.Config) {
			c.Guardrail.Connectors["codex"] = config.PerConnectorGuardrailConfig{BlockAt: "HIGH"}
		},
		"connector alert_at": func(c *config.Config) {
			c.Guardrail.Connectors["codex"] = config.PerConnectorGuardrailConfig{AlertAt: "LOW"}
		},
	} {
		oldCfg, newCfg := pair(edit)
		if !guardrailNeedsRestart(oldCfg, newCfg) {
			t.Errorf("%s: guardrailNeedsRestart = false, want true", name)
		}
		if diff := diffConfigs(oldCfg, newCfg); !slices.Contains(diff.RestartRequired, "guardrail.connectors") {
			t.Errorf("%s: diff = %+v, want guardrail.connectors to require a restart", name, diff)
		}
	}
}
