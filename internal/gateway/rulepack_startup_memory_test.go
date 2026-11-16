// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

func TestGAP0332StartupRulePackAllocations(t *testing.T) {
	pack, err := guardrail.LoadRulePack(filepath.Join(guardrailPoliciesRoot(t), "default"))
	if err != nil {
		t.Fatal(err)
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if err := pack.Validate(); err != nil {
		t.Fatal(err)
	}
	generation, err := compileRulePackCategories(pack)
	if err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc
	t.Logf("revalidation and generation allocated %d MiB", allocated>>20)
	if allocated > 60<<20 {
		t.Fatalf("startup rule-pack allocation %d MiB exceeds 60 MiB", allocated>>20)
	}
	if len(generation.categories) == 0 {
		t.Fatal("startup rule generation is empty")
	}
}

func TestGAP0332BenignRulePackTwin(t *testing.T) {
	pack, err := guardrail.LoadRulePack(filepath.Join(guardrailPoliciesRoot(t), "default"))
	if err != nil {
		t.Fatal(err)
	}
	generation, err := compileRulePackCategories(pack)
	if err != nil {
		t.Fatal(err)
	}
	if findings := scanRuleGeneration(generation, "git status --short", "shell", ruleScanOptions{}); len(findings) != 0 {
		t.Fatalf("ordinary status command received %d findings", len(findings))
	}
}

func TestGAP0332ChangedRuleIsRechecked(t *testing.T) {
	pack, err := guardrail.LoadRulePack(filepath.Join(guardrailPoliciesRoot(t), "default"))
	if err != nil {
		t.Fatal(err)
	}
	rule := &pack.RuleFiles[0].Rules[0]
	rule.Pattern = "["
	if err := pack.Validate(); err == nil {
		t.Fatal("changed invalid pattern was accepted")
	}
	rule.Pattern = "ordinary_status_marker"
	if err := pack.Validate(); err != nil {
		t.Fatal(err)
	}
	generation, err := compileRulePackCategories(pack)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, category := range generation.categories {
		for _, compiled := range category.Rules {
			if compiled.ID == rule.ID {
				if compiled.Pattern.String() != rule.Pattern {
					t.Fatal("compiled pattern retained the previous value")
				}
				found = true
			}
		}
	}
	if !found {
		t.Fatal("changed rule was not compiled")
	}
}
