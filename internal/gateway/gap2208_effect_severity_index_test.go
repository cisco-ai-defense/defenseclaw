// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"regexp"
	"testing"
)

// TestGAP2208EffectSeverityIsIndexedPerGeneration: the severity an effects
// finding borrows from a pack rule is read from an index the generation
// builds once (live rules only, highest severity per id), not by scanning
// every category and rule of the generation, and of each meet member, per
// lookup. Red at det111/t23e6-merge f6e151801a (no index).
func TestGAP2208EffectSeverityIsIndexedPerGeneration(t *testing.T) {
	g := gap2207Generation(t,
		PatternRule{ID: "CMD-PIPE-CURL", Title: "curl piped to shell", Severity: "HIGH", ToolCallOnly: true, Pattern: regexp.MustCompile(`(?i)\bcurl\b`)},
		PatternRule{ID: "cmd-pipe-curl", Title: "curl piped to shell", Severity: "CRITICAL", ToolCallOnly: true, Expression: "false", Pattern: regexp.MustCompile(`a^`)},
		PatternRule{ID: "CMD-PIPE-WGET", Title: "wget piped to shell", Severity: "MEDIUM", ToolCallOnly: true, Pattern: regexp.MustCompile(`a^`)})
	if got := g.effectSeverity["CMD-PIPE-CURL"]; got != "HIGH" {
		t.Fatalf("index CMD-PIPE-CURL = %q, want HIGH (the live definition)", got)
	}
	if _, ok := g.effectSeverity["CMD-PIPE-WGET"]; ok {
		t.Fatal("index holds the tombstoned CMD-PIPE-WGET")
	}
	meet := meetRuleGenerationWithNames([]*compiledRulePackCategories{g}, []string{"a"})
	// The lookups read the index, not the categories.
	g.categories, meet.categories = nil, nil
	if got := effectRuleSeverity(g, "cmd-pipe-curl"); got != "HIGH" {
		t.Errorf("effectRuleSeverity(generation) = %q, want HIGH from the index", got)
	}
	if got := effectRuleSeverity(meet, "CMD-PIPE-CURL"); got != "HIGH" {
		t.Errorf("effectRuleSeverity(meet) = %q, want HIGH from the member index", got)
	}
	if len(meet.effectSeverity) != 0 {
		t.Errorf("meet index has %d ids, want none (each member has its own)", len(meet.effectSeverity))
	}
}
