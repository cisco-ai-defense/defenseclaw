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

// TestProfilePosture_InjectionJudge is a contract test that pins the
// relative strictness ordering of the shipped policy profiles:
//
//	permissive  ≥  default  ≥  strict   (in terms of single-category cap)
//
// A regression here means an operator could flip to the strict
// profile and unknowingly inherit the default profile's tolerance
// for single-category injection hits (MEDIUM/alert instead of
// HIGH/block). The concrete attack class this defends against is
// the "cat my etc passwd" bypass — see TestHasSensitiveFileContext
// and TestInjectionToVerdictCtx_SensitiveContextUnCapsSingleCategory
// for the runtime-side un-cap when a sensitive-file token is in the
// prompt. This test guards the YAML contract so the boost isn't
// the only thing protecting that class.
func TestProfilePosture_InjectionJudge(t *testing.T) {
	_, selfPath, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve caller path")
	}
	// .../internal/gateway/rulepack_posture_test.go -> repo root
	repoRoot := filepath.Join(filepath.Dir(selfPath), "..", "..")
	policiesRoot := filepath.Join(repoRoot, "policies", "guardrail")

	cases := []struct {
		profile               string
		wantMinCats           int
		wantSingleCategoryCap string
	}{
		// Strict: block on a single injection category; no MEDIUM cap.
		{"strict", 1, "HIGH"},
		// Default: require two categories or rely on the sensitive-
		// file-context runtime boost.
		{"default", 2, "MEDIUM"},
		// Permissive: same cap as default — the permissive posture is
		// about rule-set breadth, not injection-cap leniency.
		{"permissive", 2, "MEDIUM"},
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

// TestProfilePosture_StrictIsStricterThanDefault makes the ordering
// constraint explicit: flipping the numbers in default/ to match
// strict/ would silently pass the individual-profile assertions
// above, so we also assert the relation between the two.
func TestProfilePosture_StrictIsStricterThanDefault(t *testing.T) {
	_, selfPath, _, _ := runtime.Caller(0)
	repoRoot := filepath.Join(filepath.Dir(selfPath), "..", "..")
	policiesRoot := filepath.Join(repoRoot, "policies", "guardrail")

	strict := guardrail.LoadRulePack(filepath.Join(policiesRoot, "strict")).InjectionJudge()
	def := guardrail.LoadRulePack(filepath.Join(policiesRoot, "default")).InjectionJudge()

	if strict.MinCategoriesForHigh > def.MinCategoriesForHigh {
		t.Errorf("strict.min_categories_for_high (%d) > default (%d); strict must be ≤ default",
			strict.MinCategoriesForHigh, def.MinCategoriesForHigh)
	}

	// severityRank is the runtime source of truth for the cap comparison.
	if severityRank[strict.SingleCategoryMaxSev] < severityRank[def.SingleCategoryMaxSev] {
		t.Errorf("strict single-category cap %q is softer than default %q",
			strict.SingleCategoryMaxSev, def.SingleCategoryMaxSev)
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
