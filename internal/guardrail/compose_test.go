// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardrail

import (
	"strings"
	"testing"
)

// TestComposeAppliesRulesLayersInOrder pins guardrail.rules composition: a
// protection pack replaces same-id rules and adds its file, then enable,
// disable, severity_overrides, suppressions and sensitive_tools apply; the
// base pack is never modified and unknown IDs are errors.
func TestComposeAppliesRulesLayersInOrder(t *testing.T) {
	base, err := LoadRulePack("")
	if err != nil {
		t.Fatal(err)
	}
	enabled := true
	base.RuleFiles = []*RulesFileYAML{{
		Version: 1, Category: "secret", SourcePath: "/packs/default/rules/secrets.yaml",
		Rules: []RuleDefYAML{
			{ID: "SEC-A", Pattern: "a+", Title: "A", Severity: "HIGH", Confidence: 0.9, Tags: []string{"t"}},
			{ID: "SEC-B", Pattern: "b+", Title: "B", Severity: "LOW", Confidence: 0.9, Tags: []string{"t"}, Enabled: &enabled},
		},
	}}
	protections := func(name string) ([]ProtectionRuleFile, error) {
		return []ProtectionRuleFile{{Name: "secrets.yaml", Data: []byte(
			"version: 1\ncategory: secret\nrules:\n  - id: SEC-A\n    pattern: 'aa+'\n    title: A2\n    severity: CRITICAL\n    confidence: 0.8\n    tags: [p]\n")}}, nil
	}
	off := false
	got, err := Compose(base, protections, Customization{
		Protections:       []string{"pack"},
		Disable:           []string{"SEC-B"},
		SeverityOverrides: map[string]string{"SEC-A": "medium"},
		Suppressions:      []FindingSuppression{{ID: "SUPP-X", FindingPattern: "^SEC-A$", Reason: "fixture"}},
		SensitiveTools:    []SensitiveToolOverride{{Name: "crm_export", ResultInspection: &enabled, JudgeResult: &off}},
	})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	a, b := got.findRule("SEC-A"), got.findRule("SEC-B")
	if a == nil || a.Title != "A2" || a.Severity != "MEDIUM" {
		t.Fatalf("SEC-A = %+v, want the protection pack's rule at MEDIUM", a)
	}
	if b == nil || b.Enabled == nil || *b.Enabled {
		t.Fatalf("SEC-B = %+v, want disabled", b)
	}
	if base.findRule("SEC-B").Enabled != &enabled || *base.findRule("SEC-B").Enabled != true || base.findRule("SEC-A").Title != "A" {
		t.Fatal("Compose modified the base pack")
	}
	if got.LookupSensitiveTool("crm_export") == nil {
		t.Fatal("sensitive tool was not merged")
	}
	if _, err := Compose(base, protections, Customization{Enable: []string{"SEC-NOPE"}}); err == nil ||
		!strings.Contains(err.Error(), "unknown rule SEC-NOPE") {
		t.Fatalf("unknown rule = %v", err)
	}
	// A disabled category remains explicit so the gateway does not restore defaults.
	base.RuleFiles = append(base.RuleFiles, &RulesFileYAML{
		Version: 1, Category: "pii", SourcePath: "/packs/default/rules/pii.yaml",
		Rules: []RuleDefYAML{{ID: "PII-A", Pattern: "p+", Title: "P", Severity: "LOW", Confidence: 0.9, Tags: []string{"t"}}},
	})
	dropped, err := Compose(base, protections, Customization{Disable: []string{"SEC-A", "SEC-B"}})
	if err != nil || len(dropped.RuleFiles) != 2 || dropped.findRule("PII-A") == nil ||
		dropped.findRule("SEC-A") == nil || *dropped.findRule("SEC-A").Enabled {
		t.Fatalf("disabled category was lost: error %v, files %+v", err, dropped.RuleFiles)
	}
}

// A custom pack can choose any file name for a category. Protection layering
// merges by the category that Validate treats as unique.
func TestComposeProtectionMergesCategoryAcrossFilenames(t *testing.T) {
	base, err := LoadRulePack("")
	if err != nil {
		t.Fatal(err)
	}
	base.RuleFiles = []*RulesFileYAML{{
		Version: 1, Category: "enterprise-data", SourcePath: "/custom/rules/customer-data.yaml",
		Rules: []RuleDefYAML{{ID: "DATA-LOCAL", Pattern: "local-marker", Title: "Local", Severity: "LOW", Confidence: 0.9, Tags: []string{"local"}}},
	}}
	protection := func(string) ([]ProtectionRuleFile, error) {
		return []ProtectionRuleFile{{Name: "enterprise-data.yaml", Data: []byte(
			"version: 1\ncategory: enterprise-data\nrules:\n  - id: DATA-PROTECTION\n    pattern: protection-marker\n    title: Protection\n    severity: HIGH\n    confidence: 0.9\n    tags: [protection]\n")}}, nil
	}
	got, err := Compose(base, protection, Customization{Protections: []string{"privacy-high-assurance"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.RuleFiles) != 1 || got.findRule("DATA-LOCAL") == nil || got.findRule("DATA-PROTECTION") == nil {
		t.Fatalf("composition split a single category: %+v", got.RuleFiles)
	}
}

func TestComposeManifestPostureChangesDigest(t *testing.T) {
	dir := t.TempDir()
	writeRulePackFile(t, dir, "rules/custom.yaml", validRulesYAML("custom", "R-1"))
	before := mustLoadRulePack(t, dir)
	layer := Customization{SeverityOverrides: map[string]string{"R-1": "LOW"}}
	composedBefore, err := Compose(before, nil, layer)
	if err != nil {
		t.Fatal(err)
	}
	writeRulePackFile(t, dir, PackManifestFile, `{"posture":"strict"}`)
	after := mustLoadRulePack(t, dir)
	composedAfter, err := Compose(after, nil, layer)
	if err != nil {
		t.Fatal(err)
	}
	if composedBefore.Summary().Digest == composedAfter.Summary().Digest {
		t.Fatal("manifest posture edit did not change composed pack digest")
	}
}
