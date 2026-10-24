// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestMeetKeepsCrossCategoryMemberRuleActions(t *testing.T) {
	resetConnectorRuleCategories(t)
	withLocalPatternsRestored(t)
	makePack := func(category, severity string) *compiledRulePackCategories {
		t.Helper()
		generation, err := compileRulePackGeneration([]ruleCategory{{Name: category, Rules: []PatternRule{provenanceRule("MEET-CROSS-CATEGORY", severity)}}})
		if err != nil {
			t.Fatal(err)
		}
		return generation
	}
	for _, order := range []struct{ a, b string }{{"CRITICAL", "LOW"}, {"LOW", "CRITICAL"}} {
		set, ctx := provenanceSet(t, nil, map[string]config.GuardrailProfile{
			"a": {Mode: "action", BlockAt: "CRITICAL"},
			"b": {Mode: "action", BlockAt: "CRITICAL"},
		}, map[string]*compiledRulePackCategories{
			"a": makePack("command", order.a),
			"b": makePack("secret", order.b),
		}, []string{"codex"})
		request := withGuardrailProfile(withProfileSurface(ctx, profileSurfaceHooks), set, "codex")
		resolved := resolvedGuardrailProfileFrom(request)
		if resolved == nil || !config.IsProfileMeet(resolved.decision.Name) {
			t.Fatal("no meet resolved")
		}
		findings := scanRuleGeneration(snapshotRulePackGenerationFor(request, "codex"), provenanceToken("MEET-CROSS-CATEGORY"), "Bash", ruleScanOptions{})
		if len(findings) != 2 {
			t.Errorf("order %+v: got %d findings, want one per member", order, len(findings))
		}
		if got := guardrailActionForConnectorFindings(resolved.derived, "codex", findings, false); got != guardrailActionBlock {
			t.Errorf("order %+v: action %s, want block", order, got)
		}
	}
}

func TestMeetPreservesMembersConfirmation(t *testing.T) {
	resetConnectorRuleCategories(t)
	withLocalPatternsRestored(t)
	generation, err := compileRulePackGeneration([]ruleCategory{{Name: "secret", Rules: []PatternRule{provenanceRule("MEET-HILT-HIGH", "HIGH")}}})
	if err != nil {
		t.Fatal(err)
	}
	empty, err := compileRulePackGeneration(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, order := range []bool{false, true} {
		profiles := map[string]config.GuardrailProfile{
			"a": {Mode: "action", BlockAt: "CRITICAL", HILT: &config.HILTConfig{Enabled: true, MinSeverity: "HIGH"}},
			"b": {Mode: "action", BlockAt: "LOW"},
		}
		packs := map[string]*compiledRulePackCategories{"a": generation, "b": empty}
		if order {
			profiles["a"], profiles["b"] = profiles["b"], profiles["a"]
			packs["a"], packs["b"] = packs["b"], packs["a"]
		}
		set, ctx := provenanceSet(t, nil, profiles, packs, []string{"codex"})
		request := withGuardrailProfile(withProfileSurface(ctx, profileSurfaceHooks), set, "codex")
		resolved := resolvedGuardrailProfileFrom(request)
		if resolved == nil || !config.IsProfileMeet(resolved.decision.Name) {
			t.Fatal("no meet resolved")
		}
		findings := scanRuleGeneration(snapshotRulePackGenerationFor(request, "codex"), provenanceToken("MEET-HILT-HIGH"), "Bash", ruleScanOptions{})
		if got := guardrailActionForConnectorFindings(resolved.derived, "codex", findings, true); got != guardrailActionConfirm {
			t.Errorf("reversed=%t: action %s, want confirm (findings %v)", order, got, FindingStrings(findings))
		}
	}
}

// A meet's synchronous result is the strongest action a member with a
// matching rule takes alone. This includes the alert band below HILT, the
// confirmation band, and a second member's block, in both assignment orders.
func TestMeetCombinesEachMembersAlertConfirmAndBlock(t *testing.T) {
	resetConnectorRuleCategories(t)
	withLocalPatternsRestored(t)
	pack := func(ids ...string) *compiledRulePackCategories {
		t.Helper()
		var rules []PatternRule
		for _, item := range ids {
			parts := strings.Split(item, "/")
			rules = append(rules, provenanceRule(parts[0], parts[1]))
		}
		generation, err := compileRulePackGeneration([]ruleCategory{{Name: "secret", Rules: rules}})
		if err != nil {
			t.Fatal(err)
		}
		return generation
	}
	first := pack("MEET-A-LOW/LOW", "MEET-A-HIGH/HIGH", "MEET-A-CRITICAL/CRITICAL")
	second := pack("MEET-B-LOW/LOW")
	for _, reversed := range []bool{false, true} {
		profiles := map[string]config.GuardrailProfile{
			"a": {Mode: "action", BlockAt: "CRITICAL", AlertAt: "LOW", HILT: &config.HILTConfig{Enabled: true, MinSeverity: "HIGH"}},
			"b": {Mode: "action", BlockAt: "LOW"},
		}
		packs := map[string]*compiledRulePackCategories{"a": first, "b": second}
		if reversed {
			profiles["a"], profiles["b"] = profiles["b"], profiles["a"]
			packs["a"], packs["b"] = packs["b"], packs["a"]
		}
		set, ctx := provenanceSet(t, nil, profiles, packs, []string{"codex"})
		for _, surface := range []profileSurfaces{profileSurfaceHooks, profileSurfaceInspect} {
			request := withGuardrailProfile(withProfileSurface(ctx, surface), set, "codex")
			resolved := resolvedGuardrailProfileFrom(request)
			if resolved == nil || !config.IsProfileMeet(resolved.decision.Name) {
				t.Fatalf("reversed=%t surface=%v: no meet", reversed, surface)
			}
			for _, id := range []string{"MEET-A-LOW", "MEET-A-HIGH", "MEET-A-CRITICAL", "MEET-B-LOW"} {
				text := provenanceToken(id)
				want := guardrailActionAllow
				for _, member := range []string{"a", "b"} {
					own := scanRuleGeneration(set.memberRuleGeneration(request, member, "codex"), text, "Bash", ruleScanOptions{})
					want = strongerGuardrailAction(want, guardrailActionForConnectorFindings(set.profileConfig(member), "codex", own, true))
				}
				findings := scanRuleGeneration(snapshotRulePackGenerationFor(request, "codex"), text, "Bash", ruleScanOptions{})
				if got := guardrailActionForConnectorFindings(resolved.derived, "codex", findings, true); got != want {
					t.Errorf("reversed=%t surface=%v rule=%s: got %s, want %s", reversed, surface, id, got, want)
				}
				if got := guardrailContentActionForFindings(resolved.derived, "codex", findings, true); got != want {
					t.Errorf("content reversed=%t surface=%v rule=%s: got %s, want %s", reversed, surface, id, got, want)
				}
			}
		}
	}
}
