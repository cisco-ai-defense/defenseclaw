// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// The union of a meet's member generations may spend, in one semantic
// dispatch, the cost budget of every member, so the rules of the last
// member are evaluated as they are alone; a generation of its own keeps
// the default budget.
func TestMeetUnionDispatchBudgetIsItsMembers(t *testing.T) {
	a, err := compileRulePackGeneration([]ruleCategory{{Name: "cmd", Rules: []PatternRule{{ID: "BUDGET-A", Expression: "false", Title: "a", Severity: "LOW"}}}})
	if err != nil {
		t.Fatal(err)
	}
	b, err := compileRulePackGeneration([]ruleCategory{{Name: "cmd", Rules: []PatternRule{{ID: "BUDGET-B", Expression: "false", Title: "b", Severity: "LOW"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if a.dispatchMaxCost() != trustedActionDispatchMaxCost {
		t.Fatalf("a generation's budget %d; want %d", a.dispatchMaxCost(), trustedActionDispatchMaxCost)
	}
	ab := mergeRuleGenerations([]*compiledRulePackCategories{a, b})
	if ab.dispatchMaxCost() != 2*trustedActionDispatchMaxCost {
		t.Fatalf("the union's budget %d; want both members' %d", ab.dispatchMaxCost(), 2*trustedActionDispatchMaxCost)
	}
	abc := mergeRuleGenerations([]*compiledRulePackCategories{ab, a})
	if abc.dispatchMaxCost() != 3*trustedActionDispatchMaxCost || len(abc.semanticRules) != 2 {
		t.Fatalf("a union of a union: budget %d, %d rules", abc.dispatchMaxCost(), len(abc.semanticRules))
	}
	member := &meetRuleMember{name: "a"}
	copyOfAB := ab.withMeetMember(member)
	if copyOfAB.dispatchMaxCost() != ab.dispatchMaxCost() || len(copyOfAB.semanticRules) != len(ab.semanticRules) {
		t.Fatalf("member copy: budget %d, %d rules", copyOfAB.dispatchMaxCost(), len(copyOfAB.semanticRules))
	}
	for _, rule := range copyOfAB.semanticRules {
		if rule.rule.meetMember != member {
			t.Fatal("member copy lost rule provenance")
		}
	}
}
