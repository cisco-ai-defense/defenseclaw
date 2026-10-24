// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// budgetReuseGeneration has fill semantic rules prefix-NNN that match
// `echo hi`, each its own expression, with rule BUD-X at severity, whose
// expression every pack shares, at position at among them, and, when own is
// set, a rule prefix-OWN with its own expression after them.
func budgetReuseGeneration(t *testing.T, prefix string, fill, at int, severity string, own bool) *compiledRulePackCategories {
	t.Helper()
	rule := func(id, severity string) PatternRule {
		return PatternRule{ID: id, Title: id, Pattern: regexp.MustCompile(regexp.QuoteMeta(strings.ToLower(id) + "_marker")),
			Expression: "f.commands.exists(c, c.program == 'echo') && '" + id + "' != ''",
			Severity:   severity, Confidence: 0.99, ToolCallOnly: true}
	}
	var rules []PatternRule
	for i := range fill {
		rules = append(rules, rule(fmt.Sprintf("%s-%03d", prefix, i), "HIGH"))
	}
	rules = slices.Insert(rules, at, rule("BUD-X", severity))
	if own {
		rules = append(rules, rule(prefix+"-OWN", "HIGH"))
	}
	compiled, err := compileRulePackGeneration([]ruleCategory{{Name: "command", Rules: rules}})
	if err != nil {
		t.Fatal(err)
	}
	return compiled
}

// A strictest combination's members share one semantic budget, but an
// expression one member judged costs the next nothing more, so it still
// counts once the budget is spent (loop round 2 review). Profile a is the
// first assignment and spends the whole budget on its own rules and BUD-X at LOW;
// profile b defines BUD-X with the same expression at HIGH, and a rule of
// its own. The meet keeps b's HIGH finding at no extra cost, wherever BUD-X
// sits in a's rules and also when a's last evaluation went past the budget,
// BUD-X's own included; b's own rule, a new evaluation, is still not judged
// past it.
func TestMeetReusesAJudgedExpressionAfterTheBudgetIsSpent(t *testing.T) {
	stubProfileSources(t)
	const command = "echo hi"
	call := trustedActionRequest{Input: actionfacts.Input{Tool: "shell", Command: command, CWD: "/repo"},
		LegacyText: command, Connector: "codex", EnforcementCapable: true}
	for _, tc := range []struct {
		name string
		at   int
		over bool
	}{
		{name: "spent exactly/shared rule last", at: 20},
		{name: "spent exactly/shared rule first", at: 0},
		{name: "last evaluation past the budget", at: 10, over: true},
		// a's last evaluation, the one past the budget, is BUD-X's: a does
		// not count it, as one profile does not, but b reuses it.
		{name: "shared rule judged past the budget", at: 20, over: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := budgetReuseGeneration(t, "REU-A", 20, tc.at, "LOW", false)
			b := budgetReuseGeneration(t, "REU-B", 0, 0, "HIGH", true)
			request := call
			request.generation, request.budget = a, newTrustedActionBudget(false)
			findingsA := dispatchTrustedAction(t.Context(), request)
			costA := request.budget.consumed
			if x := findingWithID(findingsA, "BUD-X"); x == nil || x.Severity != "LOW" || costA == 0 {
				t.Fatalf("fixture: a alone finds BUD-X %+v at cost %d", x, costA)
			}
			previous := trustedActionDispatchMaxCost
			trustedActionDispatchMaxCost = costA
			if tc.over {
				trustedActionDispatchMaxCost = costA - 1
			}
			t.Cleanup(func() { trustedActionDispatchMaxCost = previous })

			root := t.TempDir()
			profiles := map[string]config.GuardrailProfile{
				"a": {Mode: "action", BlockAt: "HIGH", RulePackDir: meetRulePackDir(t, root, "REU-A")},
				"b": {Mode: "action", BlockAt: "HIGH", RulePackDir: meetRulePackDir(t, root, "REU-B")},
			}
			set, _ := meetOfTwoAssignments(t, "action", profiles, "a", "b", "codex")
			set.rules[effectiveRulePackKey(set.profiles["a"].Config, "codex")] = a
			set.rules[effectiveRulePackKey(set.profiles["b"].Config, "codex")] = b
			set.missing = nil
			ctx := meetFixtureContext(t, set, "codex")
			g := resolvedGuardrailProfileFrom(ctx).ruleGenerationFor(ctx, "codex")
			if g == nil || len(g.members) != 2 {
				t.Fatalf("fixture: wanted a two-member meet; decision %+v", resolvedGuardrailProfileFrom(ctx).decision)
			}
			if !slices.Contains(generationRuleIDs(g.members[0]), "REU-A-000") {
				t.Fatalf("fixture: a is not first: decision %+v, first IDs %v", resolvedGuardrailProfileFrom(ctx).decision, generationRuleIDs(g.members[0]))
			}

			budget := newTrustedActionBudget(true)
			request = call
			request.generation, request.budget = g, budget
			findings := dispatchTrustedAction(ctx, request)
			if budget.consumed != costA || !budget.reached {
				t.Errorf("meet cost %d (reached %v); want a's alone (%d): b's shared expression costs nothing more", budget.consumed, budget.reached, costA)
			}
			x := findingWithID(findings, "BUD-X")
			if x == nil || x.Severity != "HIGH" || !x.contributesToEnforcement() {
				t.Fatalf("meet: BUD-X %+v; want b's HIGH finding, which blocks at block_at HIGH", x)
			}
			if own := findingWithID(findings, "REU-B-OWN"); own != nil && own.contributesToEnforcement() {
				t.Errorf("meet: b's own rule %+v was judged past the budget", own)
			}
		})
	}
}

// The first proven assignment used to decide alone. In a meet it must still
// have a chance to judge its rules before another member spends their one
// shared semantic budget, even when the member names sort the other way.
func TestMeetJudgesFirstAssignedProfileBeforeOtherMembersSpendBudget(t *testing.T) {
	stubProfileSources(t)
	rule := func(id, program string) PatternRule {
		return PatternRule{
			ID: id, Title: id, Pattern: regexp.MustCompile(regexp.QuoteMeta(strings.ToLower(id) + "_marker")),
			Expression: "f.commands.exists(c, c.program == '" + program + "') && '" + id + "' != ''",
			Severity:   "HIGH", Confidence: 0.99, ToolCallOnly: true,
		}
	}
	var filler []PatternRule
	for i := range 20 {
		filler = append(filler, rule(fmt.Sprintf("ORD-A-%03d", i), "never"))
	}
	a, err := compileRulePackGeneration([]ruleCategory{{Name: "command", Rules: filler}})
	if err != nil {
		t.Fatal(err)
	}
	b, err := compileRulePackGeneration([]ruleCategory{{Name: "command", Rules: []PatternRule{rule("ORD-B", "echo")}}})
	if err != nil {
		t.Fatal(err)
	}
	const command = "echo hi"
	request := trustedActionRequest{Input: actionfacts.Input{Tool: "shell", Command: command, CWD: "/repo"},
		LegacyText: command, Connector: "codex", EnforcementCapable: true, generation: a, budget: newTrustedActionBudget(false)}
	if findings := dispatchTrustedAction(t.Context(), request); findingWithID(findings, "ORD-A-000") != nil || request.budget.consumed == 0 {
		t.Fatalf("fixture: nonmatching a rules cost %d, findings %+v", request.budget.consumed, findings)
	}
	previous := trustedActionDispatchMaxCost
	trustedActionDispatchMaxCost = request.budget.consumed
	t.Cleanup(func() { trustedActionDispatchMaxCost = previous })

	root := t.TempDir()
	profiles := map[string]config.GuardrailProfile{
		"a": {Mode: "action", BlockAt: "HIGH", RulePackDir: meetRulePackDir(t, root, "ORD-A")},
		"b": {Mode: "action", BlockAt: "HIGH", RulePackDir: meetRulePackDir(t, root, "ORD-B")},
	}
	set, ctx := meetOfTwoAssignments(t, "observe", profiles, "b", "a", "codex")
	set.rules[effectiveRulePackKey(set.profiles["a"].Config, "codex")] = a
	set.rules[effectiveRulePackKey(set.profiles["b"].Config, "codex")] = b
	set.missing = nil
	decision := resolvedGuardrailProfileFrom(ctx).decision
	if decision.Refused != "" || len(decision.Candidates) != 2 || decision.Candidates[0] != "b" {
		t.Fatalf("fixture: first assigned profile is not b: %+v", decision)
	}
	g := resolvedGuardrailProfileFrom(ctx).ruleGenerationFor(ctx, "codex")
	if g == nil || len(g.members) != 2 {
		t.Fatal("fixture: expected a two-member meet")
	}
	request.generation, request.budget = g, newTrustedActionBudget(true)
	findings := dispatchTrustedAction(ctx, request)
	if x := findingWithID(findings, "ORD-B"); x == nil || !x.contributesToEnforcement() {
		t.Fatalf("first assigned b's unique rule was skipped: %+v (cost %d)", findings, request.budget.consumed)
	}
}
