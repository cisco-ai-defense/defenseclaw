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
	// The pin is the digest of the pack's own files (the one use-pack and
	// the migration write), not of the embedded defaults it inherits.
	pin, err := guardrail.RulePackDigest(custom.Guardrail.CustomPacks["acme"].Path)
	if err != nil {
		t.Fatal(err)
	}
	custom.Guardrail.CustomPacks["acme"] = config.CustomRulePack{Path: custom.Guardrail.CustomPacks["acme"].Path, Digest: "sha256:" + pin}
	if _, err := build(custom); err != nil {
		t.Fatalf("custom pack pinned by its files digest: %v", err)
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

// The watcher follows every single-file asset the effective digest covers.
func TestGenerationAssetFilesFollowTheDigestedFiles(t *testing.T) {
	cfg := &config.Config{}
	cfg.AIDiscovery.SignaturePacks = []string{"/p/sig.json"}
	cfg.AIDiscovery.ConfidencePolicyPath = "/p/confidence.yaml"
	cfg.Scanners.SkillScanner.PolicyFile.Path = "/p/policy.yaml"
	cfg.Scanners.MCPScanner.YARA.ExtraRules = []config.AssetFileRef{{Path: "/p/extra.yar"}}
	cfg.LLMProviders.Custom = []config.LLMCustomProvider{{Name: "acme", TLS: &config.LLMCustomProviderTLS{CACertFile: "/p/ca.pem"}}}
	got := strings.Join(generationAssetFiles(cfg), ",")
	want := strings.Join([]string{
		filepath.Clean("/p/ca.pem"), filepath.Clean("/p/confidence.yaml"), filepath.Clean("/p/extra.yar"),
		filepath.Clean("/p/policy.yaml"), filepath.Clean("/p/sig.json"),
	}, ",")
	if got != want {
		t.Fatalf("asset files = %s, want %s", got, want)
	}
	if _, ok := assetDigestComponents(cfg)["provider_ca:acme"]; !ok {
		t.Fatal("the provider CA file is not in the effective digest")
	}
}

// A policy directory without Rego is the managed packages' config-driven mode:
// the generation has no OPA and no error to report (GAP-0021).
func TestBuildGenerationTreatsMissingRegoAsNoOPA(t *testing.T) {
	for _, strict := range []bool{false, true} {
		g, err := buildGeneration(context.Background(), generationInputs{cfg: &config.Config{PolicyDir: t.TempDir()}, strictOPA: strict})
		if err != nil {
			t.Fatalf("strict=%v empty policy dir: %v, want no error", strict, err)
		}
		if g.OPA != nil || g.opaError != "" {
			t.Fatalf("strict=%v empty policy dir: OPA=%v opaError=%q, want no OPA and no error", strict, g.OPA, g.opaError)
		}
	}
}

// A corrupt Rego module rejects a (strict) reload build, so the previous
// generation stays and last_reload_error names the file; boot falls back
// (GAP-0043).
func TestBuildGenerationRejectsACorruptModuleOnlyWhenStrict(t *testing.T) {
	policyDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(policyDir, "bad.rego"), []byte("package defenseclaw\nnot rego {"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{PolicyDir: policyDir}
	if _, err := buildGeneration(context.Background(), generationInputs{cfg: cfg, strictOPA: true}); err == nil || !strings.Contains(err.Error(), "bad.rego") {
		t.Fatalf("strict build with a corrupt module = %v, want a parse error naming the file", err)
	}
	g, err := buildGeneration(context.Background(), generationInputs{cfg: cfg})
	if err != nil || g.opaError == "" {
		t.Fatalf("boot build with a corrupt module: err=%v opaError=%q, want the fallback with its reason", err, g.opaError)
	}
}
