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
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
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
			}
			ij := rp.InjectionJudge()
			if ij == nil {
				t.Fatalf("profile=%s has no InjectionJudge config", tc.profile)
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

// TestProfilePosture_TaintStateConfig pins the relative strictness
// ordering of the per-profile taint state config (taint.yaml). The
// state file controls how long credentials/files stay tainted in the
// session and which network destinations are excluded — knobs the
// Rego policy reads as data only (escalation steps and confidence
// floors live in policies/rego/data.json and have their own ordering
// asserted by Rego unit tests).
//
// Contract:
//   - strict has the longest decay window (slowest to forget)
//   - permissive has the shortest decay window (fastest to forget)
//   - strict has at least as many sensitive_files as default
//   - permissive has at least as many network_exclusions as default
//     (so legitimate background loops aren't tarred as exfil)
func TestProfilePosture_TaintStateConfig(t *testing.T) {
	_, selfPath, _, _ := runtime.Caller(0)
	repoRoot := filepath.Join(filepath.Dir(selfPath), "..", "..")
	policiesRoot := filepath.Join(repoRoot, "policies", "guardrail")

	load := func(profile string) *guardrail.TaintStateConfig {
		rp := guardrail.LoadRulePack(filepath.Join(policiesRoot, profile))
		if rp == nil || rp.Taint == nil {
			t.Fatalf("profile=%s: missing taint.yaml", profile)
		}
		return rp.Taint
	}
	strict := load("strict")
	def := load("default")
	permissive := load("permissive")

	// Decay windows: strict ≥ default ≥ permissive (slowest forget).
	if !(strict.FlagDecayEvents >= def.FlagDecayEvents && def.FlagDecayEvents >= permissive.FlagDecayEvents) {
		t.Errorf("flag_decay_events ordering violated: strict=%d default=%d permissive=%d (want strict ≥ default ≥ permissive)",
			strict.FlagDecayEvents, def.FlagDecayEvents, permissive.FlagDecayEvents)
	}
	if !(strict.FileTaintDecayEvents >= def.FileTaintDecayEvents && def.FileTaintDecayEvents >= permissive.FileTaintDecayEvents) {
		t.Errorf("file_taint_decay_events ordering violated: strict=%d default=%d permissive=%d",
			strict.FileTaintDecayEvents, def.FileTaintDecayEvents, permissive.FileTaintDecayEvents)
	}

	// Sensitive-file coverage: strict should match-or-exceed default.
	// Permissive may shrink the set, but never to zero — that would
	// silently disable file-level taint propagation.
	if len(strict.SensitiveFiles) < len(def.SensitiveFiles) {
		t.Errorf("strict.sensitive_files (%d) is shorter than default (%d); strict should match-or-exceed",
			len(strict.SensitiveFiles), len(def.SensitiveFiles))
	}
	if len(permissive.SensitiveFiles) == 0 {
		t.Errorf("permissive.sensitive_files is empty — file-level propagation effectively disabled")
	}

	// Network exclusions are the operator's safety valve for noisy
	// internal services. Permissive should have at least as many as
	// default so legitimate background traffic doesn't trip the
	// weak-consumer path.
	if len(permissive.NetworkExclusions) < len(def.NetworkExclusions) {
		t.Errorf("permissive.network_exclusions (%d) shorter than default (%d); permissive should be at least as forgiving",
			len(permissive.NetworkExclusions), len(def.NetworkExclusions))
	}

	// All three profiles must set a positive idle TTL — a zero value
	// would never evict an idle session from the tracker.
	for _, p := range []struct {
		name string
		c    *guardrail.TaintStateConfig
	}{
		{"strict", strict}, {"default", def}, {"permissive", permissive},
	} {
		if p.c.SessionIdleTTLSeconds <= 0 {
			t.Errorf("profile=%s: session_idle_ttl_seconds must be > 0 (got %d)",
				p.name, p.c.SessionIdleTTLSeconds)
		}
		if p.c.FlagDecayEvents <= 0 {
			t.Errorf("profile=%s: flag_decay_events must be > 0 (got %d)", p.name, p.c.FlagDecayEvents)
		}
		if p.c.FileTaintDecayEvents <= 0 {
			t.Errorf("profile=%s: file_taint_decay_events must be > 0 (got %d)", p.name, p.c.FileTaintDecayEvents)
		}
	}
}

// TestRegoTaintKnobOrdering pins the policy-side taint escalation
// knobs (data.guardrail.taint.<tier>) by reading policies/rego/
// data.json directly. The Rego unit tests already cover behavior;
// this test covers the *contract* between operator-selected tier
// names and their numeric knobs so a refactor that flips two values
// is caught at Go test time, not by an integration failure.
//
// Contract:
//   - mode: strict/default = "action", permissive = "observe"
//   - escalation_steps_strong: strict ≥ default ≥ permissive
//   - escalation_steps_weak:   strict ≥ default ≥ permissive
//   - min_consumer_confidence: strict ≤ default ≤ permissive
//     (strict accepts lower-confidence consumers; permissive demands
//     near-certainty before bumping severity)
func TestRegoTaintKnobOrdering(t *testing.T) {
	_, selfPath, _, _ := runtime.Caller(0)
	repoRoot := filepath.Join(filepath.Dir(selfPath), "..", "..")
	dataPath := filepath.Join(repoRoot, "policies", "rego", "data.json")

	raw, err := os.ReadFile(dataPath)
	if err != nil {
		t.Fatalf("read %s: %v", dataPath, err)
	}
	var doc struct {
		Guardrail struct {
			Taint map[string]struct {
				Mode                  string  `json:"mode"`
				EscalationStepsStrong int     `json:"escalation_steps_strong"`
				EscalationStepsWeak   int     `json:"escalation_steps_weak"`
				RequireTaintSource    bool    `json:"require_taint_source"`
				MinConsumerConfidence float64 `json:"min_consumer_confidence"`
			} `json:"taint"`
		} `json:"guardrail"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", dataPath, err)
	}
	tiers := doc.Guardrail.Taint
	if tiers == nil {
		t.Fatalf("data.guardrail.taint missing in %s", dataPath)
	}

	for _, name := range []string{"default", "strict", "permissive"} {
		if _, ok := tiers[name]; !ok {
			t.Fatalf("data.guardrail.taint.%s missing", name)
		}
	}
	strict, def, perm := tiers["strict"], tiers["default"], tiers["permissive"]

	if strict.Mode != "action" {
		t.Errorf("strict.mode = %q, want action", strict.Mode)
	}
	if def.Mode != "action" {
		t.Errorf("default.mode = %q, want action", def.Mode)
	}
	if perm.Mode != "observe" {
		t.Errorf("permissive.mode = %q, want observe", perm.Mode)
	}

	if !(strict.EscalationStepsStrong >= def.EscalationStepsStrong && def.EscalationStepsStrong >= perm.EscalationStepsStrong) {
		t.Errorf("escalation_steps_strong ordering violated: strict=%d default=%d permissive=%d",
			strict.EscalationStepsStrong, def.EscalationStepsStrong, perm.EscalationStepsStrong)
	}
	if !(strict.EscalationStepsWeak >= def.EscalationStepsWeak && def.EscalationStepsWeak >= perm.EscalationStepsWeak) {
		t.Errorf("escalation_steps_weak ordering violated: strict=%d default=%d permissive=%d",
			strict.EscalationStepsWeak, def.EscalationStepsWeak, perm.EscalationStepsWeak)
	}
	if !(strict.MinConsumerConfidence <= def.MinConsumerConfidence && def.MinConsumerConfidence <= perm.MinConsumerConfidence) {
		t.Errorf("min_consumer_confidence ordering violated: strict=%.2f default=%.2f permissive=%.2f (want strict ≤ default ≤ permissive)",
			strict.MinConsumerConfidence, def.MinConsumerConfidence, perm.MinConsumerConfidence)
	}
}
