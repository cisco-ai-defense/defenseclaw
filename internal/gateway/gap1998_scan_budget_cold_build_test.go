// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"regexp"
	"testing"
)

// TestGAP1998ScanBudgetIsReadAfterTheOneTimeRuleBuild is rel-1-0-10:GAP-1998:
// the first /api/v1/inspect/* call of a gateway process built the default
// rule generation (its semantic programs) and the literal plans of its rules
// inside its own 200 ms scan deadline, so on a busy host (or under -race) that
// call alone answered 504, which the plugin and the hook script block, while
// the same input answered its verdict on every later call. Every route reads
// its budget before it starts the deadline: once it has the budget, the
// generation and every rule's plan exist, and the deadline counts only the
// call's own scan. Checked by state, not by time.
func TestGAP1998ScanBudgetIsReadAfterTheOneTimeRuleBuild(t *testing.T) {
	resetConnectorRuleCategories(t)
	ruleCategoriesMu.Lock()
	allRuleGeneration, allRuleCategories = nil, nil
	ruleCategoriesMu.Unlock()
	sources := 0
	for _, category := range defaultRuleCategories() {
		for _, rule := range category.Rules {
			if rule.Pattern != nil {
				ruleLiteralPlans.Delete(rule.Pattern.String())
				sources++
			}
		}
	}
	if sources == 0 {
		t.Fatal("the default rule set has no pattern rule")
	}

	api := &APIServer{}
	if got := api.inspectScanBudget(); got != inspectScanTimeout {
		t.Fatalf("budget = %s, want the production %s", got, inspectScanTimeout)
	}
	ruleCategoriesMu.RLock()
	built := allRuleGeneration
	ruleCategoriesMu.RUnlock()
	if built == nil {
		t.Fatal("the budget was read before the default rule generation was built: the first call builds it inside its deadline")
	}
	missing := 0
	for _, category := range built.categories {
		for _, rule := range category.Rules {
			if rule.Pattern == nil {
				continue
			}
			if _, ok := ruleLiteralPlans.Load(rule.Pattern.String()); !ok {
				missing++
			}
		}
	}
	if missing > 0 {
		t.Fatalf("%d rule(s) of the built generation have no literal plan: the first scan that meets them builds it inside its deadline", missing)
	}

	// Benign twin: a later call builds nothing again, and a generation
	// published before the first call (a rule pack) is the one kept.
	api.inspectToolScanTimeout = inspectScanTimeout * 3
	if got := api.inspectScanBudget(); got != inspectScanTimeout*3 {
		t.Fatalf("budget = %s, want the test seam %s", got, inspectScanTimeout*3)
	}
	ruleCategoriesMu.RLock()
	again := allRuleGeneration
	ruleCategoriesMu.RUnlock()
	if again != built {
		t.Fatal("a second budget read rebuilt the default generation")
	}
	pack := mustCompileRulePackGeneration([]ruleCategory{{Name: "secrets", Rules: []PatternRule{{
		ID: "GAP1998-PACK", Pattern: regexp.MustCompile(`gap1998-pack-marker`), Title: "pack rule", Severity: "HIGH", Confidence: 0.9,
	}}}})
	ruleCategoriesMu.Lock()
	allRuleGeneration, allRuleCategories = pack, pack.categories
	ruleCategoriesMu.Unlock()
	api.inspectScanBudget()
	ruleCategoriesMu.RLock()
	kept := allRuleGeneration
	ruleCategoriesMu.RUnlock()
	if kept != pack {
		t.Fatal("reading the budget replaced a published rule pack generation with the default one")
	}
	if _, ok := ruleLiteralPlans.Load(`gap1998-pack-marker`); !ok {
		t.Fatal("the pack generation was compiled without its rule's literal plan")
	}
}
