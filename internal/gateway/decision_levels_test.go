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
	"context"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/policy"
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
			block, alert := guardrailThresholdRanks(resolveThresholds(cfg, tt.connector))
			if block != tt.wantBlock || alert != tt.wantAlert {
				t.Fatalf("thresholds(%q) = block %d / alert %d, want %d / %d",
					tt.connector, block, alert, tt.wantBlock, tt.wantAlert)
			}
		})
	}

	if block, alert := guardrailThresholdRanks(resolveThresholds(nil, "codex")); block != severityCritical || alert != severityMedium {
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
			block, alert := guardrailThresholdRanks(resolveGuardrailThresholds(tt.gc, tt.connector))
			if block != tt.wantBlock || alert != tt.wantAlert {
				t.Fatalf("thresholds(%q) = block %d / alert %d, want %d / %d",
					tt.connector, block, alert, tt.wantBlock, tt.wantAlert)
			}
		})
	}
}

// TestGuardrailLevelActions checks the severity → action mapping on the hook
// lane and the proxy lane, that blocking still comes before human approval,
// and that prompts, completions and other content take the same levels as
// tool calls (one threshold model).
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
		if got := guardrailActionForConnector(cfg, c.connector, c.severity, true); got != c.want {
			t.Errorf("%s %s = %q, want %q", c.connector, c.severity, got, c.want)
		}
	}
	high := []RuleFinding{{RuleID: "levels-content", Severity: "HIGH"}}
	if got := buildVerdictWithConfig(high, "completion", cfg, "", false).Action; got != guardrailActionBlock {
		t.Errorf("completion verdict with block_at HIGH = %q, want block", got)
	}
	// A hook verdict takes the requesting connector's levels.
	if got := buildVerdictWithConfig(high, "completion", cfg, "codex", false).Action; got != guardrailActionAlert {
		t.Errorf("codex completion verdict with its block_at CRITICAL = %q, want alert", got)
	}

	hilt := &config.Config{}
	hilt.Guardrail.HILT = config.HILTConfig{Enabled: true, MinSeverity: "HIGH"}
	hilt.Guardrail.BlockAt = "HIGH"
	if got := guardrailActionForConnector(hilt, "codex", "HIGH", true); got != guardrailActionBlock {
		t.Errorf("block_at HIGH + HILT HIGH: HIGH = %q, want block (blocking precedes approval)", got)
	}
	hilt.Guardrail.BlockAt = "CRITICAL"
	if got := guardrailActionForConnector(hilt, "codex", "HIGH", true); got != guardrailActionConfirm {
		t.Errorf("block_at CRITICAL + HILT HIGH: HIGH = %q, want confirm", got)
	}

	proxy := &config.GuardrailConfig{BlockAt: "MEDIUM"}
	if got := guardrailActionForGuardrailConnector(proxy, "", "MEDIUM", false); got != guardrailActionBlock {
		t.Errorf("proxy tool call block_at MEDIUM: MEDIUM = %q, want block", got)
	}
	if got := guardrailActionForGuardrailConnector(proxy, "", "LOW", false); got != guardrailActionAllow {
		t.Errorf("proxy tool call block_at MEDIUM: LOW = %q, want allow", got)
	}

	// The OpenClaw session-message prompt path takes the connector's levels.
	session := &config.GuardrailConfig{AlertAt: "MEDIUM", Connectors: map[string]config.PerConnectorGuardrailConfig{
		"openclaw": {AlertAt: "LOW"},
	}}
	if got := guardrailContentActionForGuardrail(session, "openclaw", "LOW"); got != guardrailActionAlert {
		t.Errorf("openclaw session prompt alert_at LOW: LOW = %q, want alert", got)
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
				if got := guardrailActionForConnector(cfg, "codex", "CRITICAL", true); got != guardrailActionBlock {
					t.Errorf("pack=%q block_at=%q alert_at=%q: CRITICAL = %q, want block", pack, blockAt, alertAt, got)
				}
			}
		}
	}
}

// TestGuardrailLevelsReloadClassification pins the reload contract: every
// decision reads the live configuration generation, so global and
// per-connector block_at / alert_at changes reload hot.
func TestGuardrailLevelsReloadClassification(t *testing.T) {
	base := &config.Config{}
	base.Guardrail.Enabled = true
	base.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{"codex": {}}
	for name, edit := range map[string]func(*config.Config){
		"global block_at": func(c *config.Config) { c.Guardrail.BlockAt = "HIGH" },
		"connector alert_at": func(c *config.Config) {
			c.Guardrail.Connectors["codex"] = config.PerConnectorGuardrailConfig{AlertAt: "LOW"}
		},
	} {
		newCfg := *base
		newCfg.Guardrail.Connectors = maps.Clone(base.Guardrail.Connectors)
		edit(&newCfg)
		if diff := diffConfigs(base, &newCfg); len(diff.RestartRequired) != 0 || !slices.Contains(diff.Changed, "guardrail") {
			t.Errorf("%s: diff = %+v, want a hot guardrail change", name, diff)
		}
	}
}

// TestSecureClientContentKeepsPackLevels pins Secure Client invariance for
// the one threshold model: under that integration content surfaces keep
// the rule pack's posture levels, while tool calls take block_at as before.
func TestSecureClientContentKeepsPackLevels(t *testing.T) {
	cfg := &config.Config{DeploymentMode: "managed_enterprise"}
	cfg.Guardrail.BlockAt = "HIGH"
	if !cfg.SecureClientIntegration() {
		t.Fatal("fixture is not a Secure Client configuration")
	}
	if got := guardrailContentAction(cfg, "", "HIGH", false); got != guardrailActionAlert {
		t.Errorf("Secure Client content HIGH = %q, want alert (the pack's level)", got)
	}
	if got := guardrailActionForConnector(cfg, "", "HIGH", false); got != guardrailActionBlock {
		t.Errorf("Secure Client tool call HIGH = %q, want block", got)
	}
	cfg.DeploymentMode = ""
	if got := guardrailContentAction(cfg, "", "HIGH", false); got != guardrailActionBlock {
		t.Errorf("OSS content HIGH = %q, want block (one threshold model)", got)
	}
}

// TestConfigThresholdsReadTheCustomPackManifestPosture: `policy show` runs
// where no generation build recorded the pack's manifest posture, so it reads
// the manifest itself and reports the levels the gateway enforces.
func TestConfigThresholdsReadTheCustomPackManifestPosture(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, guardrail.PackManifestFile), []byte(`{"posture":"strict"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Guardrail.RulePack = "acme-manifest-posture"
	cfg.Guardrail.CustomPacks = map[string]config.CustomRulePack{"acme-manifest-posture": {Path: dir}}
	got := ConfigThresholds(cfg, "")
	if got.Block != "MEDIUM" || got.Source != "pack-default:acme-manifest-posture" {
		t.Fatalf("policy show levels = %+v, want block MEDIUM from the strict manifest posture", got)
	}
}

// TestPackPostureFollowsTheReloadedPack: a reload that points a pack name at
// a pack without a manifest posture drops the posture the old pack had, and
// a candidate that points the name elsewhere (then is rejected) leaves the
// running generation's directory, and so its levels, alone.
func TestPackPostureFollowsTheReloadedPack(t *testing.T) {
	ref := config.RulePackRef{Name: "posture-reload-test"}
	rememberPackPosture("/packs/a", "strict")
	if got := packPosture(ref, "/packs/a"); got != "strict" {
		t.Fatalf("posture = %q, want strict", got)
	}
	rememberPackPosture("/packs/rejected", "permissive")
	if got := packPosture(ref, "/packs/a"); got != "strict" {
		t.Fatalf("posture after a rejected candidate = %q, want strict", got)
	}
	rememberPackPosture("/packs/b", "")
	if got := packPosture(ref, "/packs/b"); got != "default" {
		t.Fatalf("posture after the reload = %q, want default", got)
	}
}

// TestAlertLevelIsReportedClampedToBlock: guardrail.alert_at above block_at
// alerts at the block level, and policy show reports that level.
func TestAlertLevelIsReportedClampedToBlock(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.BlockAt = "LOW"
	cfg.Guardrail.AlertAt = "HIGH"
	if got := ConfigThresholds(cfg, ""); got.Block != "LOW" || got.Alert != "LOW" {
		t.Fatalf("levels = %+v, want block and alert LOW", got)
	}
}

// TestBuildPostureIsVisibleOnlyOnceTheGenerationPublishes: a build that is then
// rejected must not change the levels the running generation's hooks use.
func TestBuildPostureIsVisibleOnlyOnceTheGenerationPublishes(t *testing.T) {
	ref := config.RulePackRef{Name: "posture-pending-test"}
	rememberPackPosture("/packs/live", "strict")
	notePackPosture("/packs/live", "permissive")
	if got := packPosture(ref, "/packs/live"); got != "strict" {
		t.Fatalf("posture before publish = %q, want strict", got)
	}
	publishPackPostures()
	if got := packPosture(ref, "/packs/live"); got != "permissive" {
		t.Fatalf("posture after publish = %q, want permissive", got)
	}
}

// TestSecureClientProxyKeepsTheDataJSONLevels: the 1.0 proxy verdict read the
// data.json levels and trust level whatever the rule pack or block_at.
func TestSecureClientProxyKeepsTheDataJSONLevels(t *testing.T) {
	policyDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(policyDir, "rego"), 0o700); err != nil {
		t.Fatal(err)
	}
	data := `{"guardrail":{"block_threshold":3,"alert_threshold":1,"cisco_trust_level":"advisory"}}`
	if err := os.WriteFile(filepath.Join(policyDir, "rego", "data.json"), []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{DeploymentMode: "managed_enterprise", PolicyDir: policyDir}
	cfg.Guardrail.RulePack = "strict"
	if !cfg.SecureClientIntegration() {
		t.Fatal("fixture is not a Secure Client configuration")
	}
	previous := liveGeneration.Load()
	liveGeneration.Store(&Generation{Config: cfg})
	t.Cleanup(func() { liveGeneration.Store(previous) })
	if got := requestThresholds(context.Background()); got != (policy.ThresholdsInput{Block: 3, Alert: 1, CiscoTrustLevel: "advisory"}) {
		t.Fatalf("Secure Client proxy thresholds = %+v, want the data.json levels", got)
	}
}
