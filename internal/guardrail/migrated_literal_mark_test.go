// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardrail

import "testing"

// A rule written for 1.0 with the expression the 0.8.x rebase derives keeps
// that expression's meaning; only a rule the rebase marked (or the migration
// record names) also matches its literal anywhere in a tool call.
func TestMigratedLiteralRuleNeedsItsMigrationMark(t *testing.T) {
	expression := literalRuleExpression("acme-marker", false, false, false)
	if MigratedLiteralRule("acme-marker", expression, false) {
		t.Fatal("an unmarked rule is a migrated literal rule")
	}
	if !MigratedLiteralRule("acme-marker", expression, true) {
		t.Fatal("a marked rule with the derived expression is not a migrated literal rule")
	}
	if MigratedLiteralRule("acme-marker", "f.commands.exists(c, c.program == 'acme')", true) {
		t.Fatal("a mark makes any expression a migrated literal rule")
	}

	pack := &RulePack{RuleFiles: []*RulesFileYAML{{Version: 1, Category: "acme", Rules: []RuleDefYAML{
		{ID: "ACME-MIGRATED", Pattern: "acme-marker", Expression: expression},
		{ID: "ACME-OWN", Pattern: "acme-marker", Expression: expression},
		{ID: "ACME-OTHER", Pattern: "acme-marker", Expression: "f.commands.exists(c, c.program == 'acme')"},
	}}}}
	marked := MarkMigratedLiteralRules(pack, []string{"ACME-MIGRATED", "ACME-OTHER"})
	rules := marked.RuleFiles[0].Rules
	if !rules[0].MigratedLiteral || rules[1].MigratedLiteral || rules[2].MigratedLiteral {
		t.Fatalf("marks %v %v %v, want true false false", rules[0].MigratedLiteral, rules[1].MigratedLiteral, rules[2].MigratedLiteral)
	}
	if pack.RuleFiles[0].Rules[0].MigratedLiteral {
		t.Fatal("MarkMigratedLiteralRules changed its input")
	}
	if MarkMigratedLiteralRules(pack, nil) != pack {
		t.Fatal("no IDs must return the pack itself")
	}
}
