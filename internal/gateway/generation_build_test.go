// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

func repoPolicyDir(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Join(filepath.Dir(file), "..", "..", "policies")
	if _, err := os.Stat(filepath.Join(dir, "guardrail", "default")); err != nil {
		t.Skipf("policies not found: %v", err)
	}
	return dir
}

// TestBuildGenerationComposesRulesPreparesOPAAndPinsCustomPacks covers one
// generation build: rule_pack names resolve, guardrail.rules compose in
// memory (a protection pack's rules arrive, a disabled rule is off), the OPA
// queries are prepared once, the digest follows the rules, and a custom
// pack whose digest differs from config is refused.
func TestBuildGenerationComposesRulesPreparesOPAAndPinsCustomPacks(t *testing.T) {
	policyDir := repoPolicyDir(t)
	build := func(cfg *config.Config) (*Generation, error) {
		global, err := loadGlobalRulePack(guardrail.NewRulePackCache(), cfg, "global")
		if err != nil {
			return nil, err
		}
		return buildGeneration(context.Background(), generationInputs{
			cfg:       cfg,
			rulePacks: &sidecarRulePackCandidate{global: global, active: global},
			strictOPA: true,
		})
	}
	cfg := &config.Config{PolicyDir: policyDir}
	cfg.Guardrail.RulePack = "default"
	plain, err := build(cfg)
	if err != nil {
		t.Fatalf("build plain generation: %v", err)
	}
	if plain.OPA == nil || !strings.HasPrefix(plain.Components["rego"], "sha256:") {
		t.Fatalf("generation OPA = %v, components = %v", plain.OPA, plain.Components)
	}

	cfg.Guardrail.Rules = config.GuardrailRulesConfig{
		Protections: []string{"database-destruction-protection"},
		Disable:     []string{"SEC-AWS-KEY"},
	}
	composed, err := build(cfg)
	if err != nil {
		t.Fatalf("build composed generation: %v", err)
	}
	if composed.Digest == plain.Digest {
		t.Fatal("guardrail.rules did not change the effective digest")
	}
	rp := composed.RulePacks["global"]
	if rule := packRule(rp, "SEC-AWS-KEY"); rule == nil || rule.Enabled == nil || *rule.Enabled {
		t.Fatalf("SEC-AWS-KEY after disable = %+v", rule)
	}
	if packRule(rp, "impact.sql_unbounded_delete") == nil {
		t.Fatal("protection pack rules were not composed in")
	}

	custom := &config.Config{PolicyDir: policyDir}
	custom.Guardrail.RulePack = "acme"
	custom.Guardrail.CustomPacks = map[string]config.CustomRulePack{
		"acme": {Path: filepath.Join(policyDir, "guardrail", "strict"), Digest: "sha256:" + strings.Repeat("0", 64)},
	}
	if _, err := build(custom); err == nil || !strings.Contains(err.Error(), "does not match guardrail.custom_packs.acme.digest") {
		t.Fatalf("custom pack with a stale digest = %v, want a digest mismatch", err)
	}
}

func packRule(rp *guardrail.RulePack, id string) *guardrail.RuleDefYAML {
	for _, file := range rp.RuleFiles {
		for i := range file.Rules {
			if file.Rules[i].ID == id {
				return &file.Rules[i]
			}
		}
	}
	return nil
}
