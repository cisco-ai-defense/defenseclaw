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
			rp := guardrail.LoadRulePack(filepath.Join(policiesRoot, tc.profile))
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
			rp := guardrail.LoadRulePack(filepath.Join(policiesRoot, profile))
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
		ij := guardrail.LoadRulePack(filepath.Join(policiesRoot, profile)).InjectionJudge()
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
			rp := guardrail.LoadRulePack(filepath.Join(policiesRoot, tc.profile))
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
			rp := guardrail.LoadRulePack(filepath.Join(policiesRoot, profile))
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
			rp := guardrail.LoadRulePack(filepath.Join(policiesRoot, profile))
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
