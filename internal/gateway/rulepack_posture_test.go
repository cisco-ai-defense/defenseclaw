// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// TestProfilePosture_InjectionJudge pins the injection-judge labeling
// contract: every profile assigns HIGH on a single category and
// CRITICAL on two+ categories. Action mapping (block/alert/allow) is
// the profile-scoped knob and lives in decision.go.
func TestProfilePosture_InjectionJudge(t *testing.T) {
	_, selfPath, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve caller path")
	}
	// .../internal/gateway/rulepack_posture_test.go -> repo root
	repoRoot := filepath.Join(filepath.Dir(selfPath), "..", "..")
	policiesRoot := filepath.Join(repoRoot, "policies", "guardrail")

	cases := []struct {
		profile                   string
		wantMinCats               int
		wantSingleCategoryCap     string
		wantMinCategoriesCritical int
	}{
		{"strict", 1, "HIGH", 2},
		{"default", 1, "HIGH", 2},
		{"permissive", 1, "HIGH", 2},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.profile, func(t *testing.T) {
			rp := mustLoadRulePack(t, filepath.Join(policiesRoot, tc.profile))
			if rp == nil {
				t.Fatalf("LoadRulePack(%s) returned nil", tc.profile)
				return
			}
			ij := rp.InjectionJudge()
			if ij == nil {
				t.Fatalf("profile=%s has no InjectionJudge config", tc.profile)
				return
			}
			if ij.MinCategoriesForHigh != tc.wantMinCats {
				t.Errorf("profile=%s: min_categories_for_high = %d, want %d",
					tc.profile, ij.MinCategoriesForHigh, tc.wantMinCats)
			}
			if ij.SingleCategoryMaxSev != tc.wantSingleCategoryCap {
				t.Errorf("profile=%s: single_category_max_severity = %q, want %q",
					tc.profile, ij.SingleCategoryMaxSev, tc.wantSingleCategoryCap)
			}
			if ij.MinCategoriesForCritical != tc.wantMinCategoriesCritical {
				t.Errorf("profile=%s: min_categories_for_critical = %d, want %d",
					tc.profile, ij.MinCategoriesForCritical, tc.wantMinCategoriesCritical)
			}
		})
	}
}

func TestGuardrailPolicyProfilesHaveGoCompatibleRegexes(t *testing.T) {
	_, selfPath, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve caller path")
	}
	repoRoot := filepath.Join(filepath.Dir(selfPath), "..", "..")
	policiesRoot := filepath.Join(repoRoot, "policies", "guardrail")

	for _, profile := range []string{"strict", "default", "permissive"} {
		profile := profile
		t.Run(profile, func(t *testing.T) {
			rp := mustLoadRulePack(t, filepath.Join(policiesRoot, profile))
			if rp == nil {
				t.Fatalf("LoadRulePack(%s) returned nil", profile)
			}
			for _, rf := range rp.RuleFiles {
				for _, rule := range rf.Rules {
					if _, err := regexp.Compile(rule.Pattern); err != nil {
						t.Fatalf("%s/%s rule %s has invalid Go regexp %q: %v",
							profile, rf.Category, rule.ID, rule.Pattern, err)
					}
				}
			}
		})
	}
}

// TestProfilePosture_InjectionLabelingIsUnified asserts that injection-
// judge labeling does not vary across profiles. A single category is
// HIGH everywhere; two+ categories is CRITICAL everywhere. Posture
// differences live in decision.go (block/alert thresholds).
func TestProfilePosture_InjectionLabelingIsUnified(t *testing.T) {
	_, selfPath, _, _ := runtime.Caller(0)
	repoRoot := filepath.Join(filepath.Dir(selfPath), "..", "..")
	policiesRoot := filepath.Join(repoRoot, "policies", "guardrail")

	profiles := []string{"strict", "default", "permissive"}
	var first *guardrail.JudgeYAML
	for _, profile := range profiles {
		ij := mustLoadRulePack(t, filepath.Join(policiesRoot, profile)).InjectionJudge()
		if ij == nil {
			t.Fatalf("profile=%s missing injection judge config", profile)
		}
		if first == nil {
			first = ij
			continue
		}
		if ij.MinCategoriesForHigh != first.MinCategoriesForHigh ||
			ij.SingleCategoryMaxSev != first.SingleCategoryMaxSev ||
			ij.MinCategoriesForCritical != first.MinCategoriesForCritical {
			t.Errorf("profile=%s labeling diverges: min_high=%d cap=%q min_crit=%d; want match with first profile (%d/%q/%d)",
				profile, ij.MinCategoriesForHigh, ij.SingleCategoryMaxSev, ij.MinCategoriesForCritical,
				first.MinCategoriesForHigh, first.SingleCategoryMaxSev, first.MinCategoriesForCritical)
		}
	}
}

func TestProfilePosture_SSNIsCriticalOnlyInStrict(t *testing.T) {
	_, selfPath, _, _ := runtime.Caller(0)
	repoRoot := filepath.Join(filepath.Dir(selfPath), "..", "..")
	policiesRoot := filepath.Join(repoRoot, "policies", "guardrail")

	cases := []struct {
		profile string
		want    string
	}{
		{"strict", "CRITICAL"},
		{"default", "HIGH"},
		{"permissive", "HIGH"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.profile, func(t *testing.T) {
			rp := mustLoadRulePack(t, filepath.Join(policiesRoot, tc.profile))
			if rp == nil {
				t.Fatalf("LoadRulePack(%s) returned nil", tc.profile)
			}

			got := ""
			for _, rf := range rp.RuleFiles {
				for _, rule := range rf.Rules {
					if rule.ID == "ENT-BULK-SSN" {
						got = rule.Severity
					}
				}
			}
			if got != tc.want {
				t.Fatalf("%s ENT-BULK-SSN severity = %q, want %q", tc.profile, got, tc.want)
			}
		})
	}
}

func TestProfilePosture_ExactCredentialSignalsAreCriticalAcrossProfiles(t *testing.T) {
	_, selfPath, _, _ := runtime.Caller(0)
	repoRoot := filepath.Join(filepath.Dir(selfPath), "..", "..")
	policiesRoot := filepath.Join(repoRoot, "policies", "guardrail")

	criticalIDs := map[string]bool{
		"SEC-GOOGLE":          true,
		"SEC-SLACK-TOKEN":     true,
		"SEC-SLACK-WEBHOOK":   true,
		"SEC-DISCORD-WEBHOOK": true,
		"SEC-CONNSTR":         true,
		"SEC-SENDGRID":        true,
		"PATH-SSH-KEY":        true,
		"PATH-GIT-CREDS":      true,
		"PATH-NETRC":          true,
		"PATH-PROC-ENVIRON":   true,
		"CMD-SYSTEMCTL":       true,
	}

	for _, profile := range []string{"strict", "default", "permissive"} {
		profile := profile
		t.Run(profile, func(t *testing.T) {
			rp := mustLoadRulePack(t, filepath.Join(policiesRoot, profile))
			if rp == nil {
				t.Fatalf("LoadRulePack(%s) returned nil", profile)
			}
			seen := make(map[string]bool, len(criticalIDs))
			for _, rf := range rp.RuleFiles {
				for _, rule := range rf.Rules {
					if !criticalIDs[rule.ID] {
						continue
					}
					seen[rule.ID] = true
					if rule.Severity != "CRITICAL" {
						t.Fatalf("%s/%s severity = %q, want CRITICAL", profile, rule.ID, rule.Severity)
					}
				}
			}
			for id := range criticalIDs {
				if !seen[id] {
					t.Fatalf("%s missing expected critical rule %s", profile, id)
				}
			}
		})
	}
}

func TestProfilePosture_InjectionJudgeDocumentsFPExclusions(t *testing.T) {
	_, selfPath, _, _ := runtime.Caller(0)
	repoRoot := filepath.Join(filepath.Dir(selfPath), "..", "..")
	policiesRoot := filepath.Join(repoRoot, "policies", "guardrail")

	for _, profile := range []string{"strict", "default", "permissive"} {
		profile := profile
		t.Run(profile, func(t *testing.T) {
			rp := mustLoadRulePack(t, filepath.Join(policiesRoot, profile))
			if rp == nil || rp.InjectionJudge() == nil {
				t.Fatalf("LoadRulePack(%s) missing injection judge", profile)
			}
			prompt := rp.InjectionJudge().SystemPrompt
			for _, needle := range []string{
				"<<<SAMPLE>>>",
				"Output formatting constraints",
				"Teams chat IDs",
				"reply only OK",
			} {
				if !strings.Contains(prompt, needle) {
					t.Fatalf("%s injection prompt missing %q", profile, needle)
				}
			}
		})
	}
}

func TestGeneratedDefaultRuleCatalogMatchesShippedYAML(t *testing.T) {
	defaultPack := mustLoadRulePack(t, filepath.Join(guardrailPoliciesRoot(t), "default"))
	if defaultPack == nil {
		t.Fatal("LoadRulePack(default) returned nil")
	}

	yamlCategories := make(map[string]*guardrail.RulesFileYAML, len(defaultPack.RuleFiles))
	for _, file := range defaultPack.RuleFiles {
		if file == nil || file.Category == "" {
			continue
		}
		if _, exists := yamlCategories[file.Category]; exists {
			t.Fatalf("default YAML contains duplicate category %q", file.Category)
		}
		yamlCategories[file.Category] = file
	}
	if got, want := len(defaultRuleCategories), len(yamlCategories); got != want {
		t.Fatalf("generated category count = %d, default YAML count = %d", got, want)
	}

	seenCategories := make(map[string]bool, len(defaultRuleCategories))
	seenIDs := make(map[string]bool)
	for _, generatedCategory := range defaultRuleCategories {
		if seenCategories[generatedCategory.Name] {
			t.Fatalf("generated catalog contains duplicate category %q", generatedCategory.Name)
		}
		seenCategories[generatedCategory.Name] = true

		yamlCategory := yamlCategories[generatedCategory.Name]
		if yamlCategory == nil {
			t.Fatalf("generated category %q is absent from default YAML", generatedCategory.Name)
		}

		enabledRules := make([]guardrail.RuleDefYAML, 0, len(yamlCategory.Rules))
		for _, rule := range yamlCategory.Rules {
			if rule.Enabled != nil && !*rule.Enabled {
				continue
			}
			enabledRules = append(enabledRules, rule)
		}
		if got, want := len(generatedCategory.Rules), len(enabledRules); got != want {
			t.Fatalf("category %s generated rule count = %d, enabled YAML count = %d",
				generatedCategory.Name, got, want)
		}

		for index, generatedRule := range generatedCategory.Rules {
			yamlRule := enabledRules[index]
			if seenIDs[generatedRule.ID] {
				t.Fatalf("generated catalog contains duplicate rule id %q", generatedRule.ID)
			}
			seenIDs[generatedRule.ID] = true
			if generatedRule.ID != yamlRule.ID ||
				generatedRule.Pattern.String() != yamlRule.Pattern ||
				generatedRule.Title != yamlRule.Title ||
				generatedRule.Severity != yamlRule.Severity ||
				generatedRule.Confidence != yamlRule.Confidence ||
				strings.Join(generatedRule.Tags, "\x00") != strings.Join(yamlRule.Tags, "\x00") {
				t.Fatalf(
					"generated rule %s/%d differs from default YAML:\n generated=%s %q %q %s %.4f %v\n      yaml=%s %q %q %s %.4f %v",
					generatedCategory.Name,
					index,
					generatedRule.ID,
					generatedRule.Pattern.String(),
					generatedRule.Title,
					generatedRule.Severity,
					generatedRule.Confidence,
					generatedRule.Tags,
					yamlRule.ID,
					yamlRule.Pattern,
					yamlRule.Title,
					yamlRule.Severity,
					yamlRule.Confidence,
					yamlRule.Tags,
				)
			}
		}
	}
}

func TestProfilePosture_EnterpriseRuleEnablement(t *testing.T) {
	cases := []struct {
		profile string
		wantIDs []string
	}{
		{
			profile: "default",
			wantIDs: []string{
				"ENT-BULK-SSN",
				"ENT-CC-VISA",
				"ENT-CC-MC",
				"ENT-CC-AMEX",
				"ENT-CC-DISCOVER",
				"ENT-IBAN",
				"ENT-MEDICAL-RECORD",
				"ENT-DOB-PATTERN",
				"ENT-BULK-CSV-PII",
				"ENT-BULK-JSON-PII",
			},
		},
		{
			profile: "strict",
			wantIDs: []string{
				"ENT-BULK-SSN",
				"ENT-BULK-SSN-NOHYPHEN",
				"ENT-CC-VISA",
				"ENT-CC-MC",
				"ENT-CC-AMEX",
				"ENT-CC-DISCOVER",
				"ENT-IBAN",
				"ENT-US-PHONE",
				"ENT-EMAIL-BULK",
				"ENT-PASSPORT-US",
				"ENT-DL-CA",
				"ENT-MEDICAL-RECORD",
				"ENT-DOB-PATTERN",
				"ENT-NHS-NUMBER",
				"ENT-BULK-CSV-PII",
				"ENT-BULK-JSON-PII",
			},
		},
		{
			profile: "permissive",
			wantIDs: []string{
				"ENT-BULK-SSN",
				"ENT-CC-VISA",
				"ENT-CC-MC",
				"ENT-CC-AMEX",
				"ENT-CC-DISCOVER",
				"ENT-MEDICAL-RECORD",
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.profile, func(t *testing.T) {
			pack := mustLoadRulePack(t, filepath.Join(guardrailPoliciesRoot(t), tc.profile))
			var gotIDs []string
			for _, file := range pack.RuleFiles {
				if file == nil || file.Category != "enterprise-data" {
					continue
				}
				for _, rule := range file.Rules {
					if rule.Enabled == nil || *rule.Enabled {
						gotIDs = append(gotIDs, rule.ID)
					}
				}
			}
			if strings.Join(gotIDs, "\x00") != strings.Join(tc.wantIDs, "\x00") {
				t.Fatalf("%s enabled enterprise rules = %v, want %v", tc.profile, gotIDs, tc.wantIDs)
			}
		})
	}
}

func TestShippedProfilesContainUnicodeObfuscationRule(t *testing.T) {
	const (
		ruleID      = "OBFUSC-UNICODE-ZWSP"
		wantPattern = `(?:[A-Za-z0-9][\x{200B}\x{200C}\x{200D}\x{FEFF}][\s\S]*?){10,}`
	)
	for _, profile := range []string{"default", "strict", "permissive"} {
		profile := profile
		t.Run(profile, func(t *testing.T) {
			pack := mustLoadRulePack(t, filepath.Join(guardrailPoliciesRoot(t), profile))
			var matches []guardrail.RuleDefYAML
			for _, file := range pack.RuleFiles {
				for _, rule := range file.Rules {
					if rule.ID == ruleID {
						matches = append(matches, rule)
					}
				}
			}
			if len(matches) != 1 {
				t.Fatalf("%s contains %d copies of %s, want exactly one", profile, len(matches), ruleID)
			}
			rule := matches[0]
			if rule.Enabled != nil && !*rule.Enabled {
				t.Fatalf("%s disables %s", profile, ruleID)
			}
			if rule.Pattern != wantPattern ||
				rule.Title != "Zero-width character obfuscation" ||
				rule.Severity != "HIGH" ||
				rule.Confidence != 0.95 ||
				strings.Join(rule.Tags, "\x00") != "prompt-injection\x00obfuscation" {
				t.Fatalf("%s %s metadata differs: %+v", profile, ruleID, rule)
			}
		})
	}
}

func TestShippedProfilesKeepSharedDriftCorrections(t *testing.T) {
	cases := []struct {
		id      string
		pattern string
	}{
		{
			id:      "SEC-AWS-KEY",
			pattern: `\b(?:AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[0-9A-Z]{16,}`,
		},
		{
			id:      "CMD-ENV-DUMP",
			pattern: `(?i)(?:^|[^A-Za-z0-9_./-])(?:printenv\b|export\s+-p\b|env\s*[|>])`,
		},
	}

	for _, profile := range []string{"default", "strict", "permissive"} {
		profile := profile
		t.Run(profile, func(t *testing.T) {
			pack := mustLoadRulePack(t, filepath.Join(guardrailPoliciesRoot(t), profile))
			for _, tc := range cases {
				var patterns []string
				for _, file := range pack.RuleFiles {
					for _, rule := range file.Rules {
						if rule.ID == tc.id {
							patterns = append(patterns, rule.Pattern)
						}
					}
				}
				if len(patterns) != 1 || patterns[0] != tc.pattern {
					t.Fatalf("%s %s patterns = %q, want exactly %q", profile, tc.id, patterns, tc.pattern)
				}
			}
		})
	}
}

func TestUnicodeObfuscationRuleThresholdAndAdjacency(t *testing.T) {
	const (
		ruleID = "OBFUSC-UNICODE-ZWSP"
		zwsp   = "\u200b"
		zwnj   = "\u200c"
		zwj    = "\u200d"
		bom    = "\ufeff"
	)
	cases := []struct {
		name      string
		text      string
		wantMatch bool
	}{
		{
			name:      "ten mixed zero-width characters",
			text:      "a" + zwsp + "b" + zwnj + "c" + zwj + "d" + bom + "e" + zwsp + "f" + zwnj + "g" + zwj + "h" + bom + "i" + zwsp + "j" + zwnj,
			wantMatch: true,
		},
		{
			name:      "nine occurrences",
			text:      strings.Repeat("a"+zwsp, 9),
			wantMatch: false,
		},
		{
			name:      "single copied zero-width character",
			text:      "copy" + zwsp + "paste",
			wantMatch: false,
		},
		{
			name:      "emoji ZWJ sequence",
			text:      strings.Repeat("👩"+zwj+"💻", 10),
			wantMatch: false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			found := false
			for _, finding := range ScanAllRules(tc.text, "read_file") {
				if finding.RuleID == ruleID {
					found = true
					if finding.Severity != "HIGH" || finding.Confidence != 0.95 {
						t.Fatalf("%s finding metadata = %+v", ruleID, finding)
					}
				}
			}
			if found != tc.wantMatch {
				t.Fatalf("%s match = %v, want %v", ruleID, found, tc.wantMatch)
			}
		})
	}
}

func guardrailPoliciesRoot(t *testing.T) string {
	t.Helper()
	_, selfPath, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve caller path")
	}
	return filepath.Join(filepath.Dir(selfPath), "..", "..", "policies", "guardrail")
}
