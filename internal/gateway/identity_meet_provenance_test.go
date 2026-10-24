// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// provenanceRule is a pattern rule that matches its own token.
func provenanceRule(id, severity string) PatternRule {
	return PatternRule{ID: id, Pattern: regexp.MustCompile(regexp.QuoteMeta(provenanceToken(id))), Title: id, Severity: severity, Confidence: 0.9}
}

func provenanceToken(id string) string { return strings.ToLower(id) + "_token" }

// provenanceSet is a profile set whose profiles "a" and "b", both assigned
// to the test group, scan with packs[name] for every connector of
// connectors, and the proven subject of that group.
func provenanceSet(t *testing.T, base func(*config.Config), profiles map[string]config.GuardrailProfile,
	packs map[string]*compiledRulePackCategories, connectors []string) (*guardrailProfileSet, context.Context) {
	t.Helper()
	p := identityTestPlatforms[0]
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	if base != nil {
		base(cfg)
	}
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{"watch": {Mode: "observe"}}
	for name, profile := range profiles {
		profile.RulePackDir = "/nonexistent/defenseclaw-meet-" + name
		cfg.Guardrail.Profiles[name] = profile
	}
	for _, name := range []string{"a", "b"} {
		cfg.Guardrail.ProfileAssignments = append(cfg.Guardrail.ProfileAssignments,
			config.ProfileAssignment{Profile: name, Match: config.ProfileMatch{Groups: []string{p.group}}})
	}
	cfg.Guardrail.DefaultProfile = "watch"
	set, err := newGuardrailProfileSet(cfg, nil, false)
	if err != nil || set == nil {
		t.Fatalf("profile set: %v", err)
	}
	for name, generation := range packs {
		for _, connectorName := range connectors {
			set.rules[effectiveRulePackKey(set.profiles[name].Config, connectorName)] = generation
		}
	}
	stubProfileSources(t)
	return set, context.WithValue(t.Context(), testVerifiedSubjectKey{}, identityTestSubject(p, p.providers[1], stateProven, true))
}

// blocksText reports whether cfg, scanning text with generation, blocks it
// for connectorName on a surface whose mode is mode.
func blocksText(cfg *config.Config, generation *compiledRulePackCategories, connectorName, mode, text string) (bool, []RuleFinding) {
	findings := scanRuleGeneration(generation, text, "Bash", ruleScanOptions{})
	return mode == "action" && len(findings) > 0 &&
		guardrailActionForConnector(cfg, connectorName, HighestSeverity(findings), false) == guardrailActionBlock, findings
}

// Review of r104 Q-identity (review at 9e7531fb): the meet of profiles
// scanned every member's rules on every surface and applied them at the
// levels of the members that enforce there. An inspect-only member's
// CRITICAL rule blocked a hook at the hook member's CRITICAL level, though
// neither member alone blocks it; so did a rule of a member that acts at
// CRITICAL at another member's LOW, and a weaker definition of one rule ID
// hid a member's stronger one. On every surface, connector and rule, the
// meet now blocks exactly where one of its members, scanning with its own
// pack at its own levels, blocks.
func TestMeetBlocksARuleOnlyWhereItsMemberWould(t *testing.T) {
	resetConnectorRuleCategories(t)
	withLocalPatternsRestored(t)
	pack := func(member, redefined string) *compiledRulePackCategories {
		var rules []PatternRule
		for _, severity := range []string{"LOW", "MEDIUM", "HIGH", "CRITICAL"} {
			rules = append(rules, provenanceRule("MEET-"+strings.ToUpper(member)+"-"+severity, severity))
		}
		rules = append(rules, provenanceRule("MEET-SHARED", "HIGH"), provenanceRule("MEET-REDEFINED", redefined))
		generation, err := compileRulePackGeneration([]ruleCategory{{Name: "secret", Rules: rules}})
		if err != nil {
			t.Fatal(err)
		}
		return generation
	}
	var texts []string
	for _, member := range []string{"A", "B"} {
		for _, severity := range []string{"LOW", "MEDIUM", "HIGH", "CRITICAL"} {
			texts = append(texts, provenanceToken("MEET-"+member+"-"+severity))
		}
	}
	texts = append(texts, provenanceToken("MEET-SHARED"), provenanceToken("MEET-REDEFINED"))
	codex := func(mode, blockAt string) map[string]config.PerConnectorGuardrailConfig {
		return map[string]config.PerConnectorGuardrailConfig{"codex": {Mode: mode, BlockAt: blockAt}}
	}
	surfaces := []struct {
		name    string
		surface profileSurfaces
		mode    func(*config.Config, string) string
	}{
		{"hooks", profileSurfaceHooks, hookModeForConfig},
		{"inspect", profileSurfaceInspect, inspectMode},
	}
	connectors := []string{"codex", "claudecode", ""}
	for _, tc := range []struct {
		name     string
		base     func(*config.Config)
		profiles map[string]config.GuardrailProfile
		// covers: one member enforces at least what the other does, so it
		// applies under its own name and no meet is resolved.
		covers bool
	}{
		{name: "hooks act at CRITICAL in one member, the other only inspects, at LOW", base: func(c *config.Config) {
			c.Guardrail.Mode, c.Codex.Mode = "action", "observe"
		}, profiles: map[string]config.GuardrailProfile{"a": {Connectors: codex("action", "CRITICAL")}, "b": {BlockAt: "LOW"}}},
		{name: "inspect acts in one member, the other only hooks", base: func(c *config.Config) {
			c.Guardrail.Mode, c.Codex.Mode = "observe", "action"
		}, profiles: map[string]config.GuardrailProfile{"a": {BlockAt: "LOW"}, "b": {Connectors: codex("action", "HIGH")}}},
		{name: "both act, at CRITICAL and at LOW", base: func(c *config.Config) {
			c.Guardrail.Mode, c.Codex.Mode = "action", "action"
		}, profiles: map[string]config.GuardrailProfile{"a": {BlockAt: "CRITICAL"}, "b": {BlockAt: "LOW"}}},
		{name: "both act at CRITICAL", base: func(c *config.Config) {
			c.Guardrail.Mode, c.Codex.Mode = "action", "action"
		}, profiles: map[string]config.GuardrailProfile{"a": {BlockAt: "CRITICAL"}, "b": {BlockAt: "CRITICAL"}}},
		{name: "one member acts, the other observes everything", profiles: map[string]config.GuardrailProfile{
			"a": {Mode: "action", BlockAt: "HIGH"}, "b": {Mode: "observe", BlockAt: "LOW"}}, covers: true},
		{name: "a member acts for Codex at MEDIUM, the other globally at LOW but observes Codex", profiles: map[string]config.GuardrailProfile{
			"a": {Connectors: codex("action", "MEDIUM")}, "b": {Mode: "action", BlockAt: "LOW", Connectors: codex("observe", "")}}},
	} {
		for _, redefinedFirst := range []string{"LOW", "CRITICAL"} {
			t.Run(fmt.Sprintf("%s, the first member's redefined rule %s", tc.name, redefinedFirst), func(t *testing.T) {
				other := map[string]string{"LOW": "CRITICAL", "CRITICAL": "LOW"}[redefinedFirst]
				packs := map[string]*compiledRulePackCategories{"a": pack("a", redefinedFirst), "b": pack("b", other)}
				set, ctx := provenanceSet(t, tc.base, tc.profiles, packs, connectors)
				meets := 0
				for _, connectorName := range connectors {
					for _, s := range surfaces {
						request := withGuardrailProfile(withProfileSurface(ctx, s.surface), set, connectorName)
						resolved := resolvedGuardrailProfileFrom(request)
						if resolved == nil || resolved.derived == nil {
							t.Fatalf("request for %q on the %s: no profile resolved", connectorName, s.name)
						}
						if config.IsProfileMeet(resolved.decision.Name) {
							meets++
						}
						meet := snapshotRulePackGenerationFor(request, connectorName)
						for _, text := range texts {
							want, wantBy := false, ""
							for _, member := range []string{"a", "b"} {
								cfg := set.profileConfig(member)
								if blocks, _ := blocksText(cfg, set.memberRuleGeneration(request, member, connectorName), connectorName, s.mode(cfg, connectorName), text); blocks {
									want, wantBy = true, member
								}
							}
							got, findings := blocksText(resolved.derived, meet, connectorName, s.mode(resolved.derived, connectorName), text)
							if got != want {
								t.Errorf("request for %q on the %s, %s: the meet blocks %t (findings %v); a member blocks %t (%s)",
									connectorName, s.name, text, got, FindingStrings(findings), want, wantBy)
							}
						}
					}
				}
				if meets == 0 && !tc.covers {
					t.Fatal("no request resolved a meet of the two profiles")
				}
			})
		}
	}
}

// Review of r104 Q-identity (review at 9e7531fb): two members' packs whose
// semantic rules together exceed the limit of one generation did not merge,
// and the meet scanned with the larger pack alone, so a CRITICAL rule only
// the other pack has was allowed. The meet now combines the members'
// compiled rules without compiling them again, in either order.
func TestMeetOfPacksPastOneGenerationsLimitsKeepsEveryMembersRules(t *testing.T) {
	resetConnectorRuleCategories(t)
	withLocalPatternsRestored(t)
	semantic := func(prefix string, n int) []PatternRule {
		rules := make([]PatternRule, 0, n)
		for i := range n {
			id := fmt.Sprintf("%s-%03d", prefix, i)
			rules = append(rules, PatternRule{ID: id, Expression: "false", Title: id, Severity: "LOW", Confidence: 0.5})
		}
		return rules
	}
	large, err := compileRulePackGeneration([]ruleCategory{{Name: "cmd", Rules: semantic("MEETCAP-LARGE", 200)}})
	if err != nil {
		t.Fatal(err)
	}
	small, err := compileRulePackGeneration([]ruleCategory{
		{Name: "cmd", Rules: semantic("MEETCAP-SMALL", 100)},
		{Name: "secret", Rules: []PatternRule{provenanceRule("MEETCAP-SMALL-SECRET", "CRITICAL")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := compileRulePackGeneration(append(append([]ruleCategory(nil), large.categories...), small.categories...)); err == nil {
		t.Fatal("the two packs compile as one generation; the test needs them past its limits")
	}
	profiles := map[string]config.GuardrailProfile{"a": {Mode: "action", BlockAt: "CRITICAL"}, "b": {Mode: "action", BlockAt: "CRITICAL"}}
	for _, order := range [][2]*compiledRulePackCategories{{large, small}, {small, large}} {
		set, ctx := provenanceSet(t, nil, profiles, map[string]*compiledRulePackCategories{"a": order[0], "b": order[1]}, []string{"codex"})
		for _, surface := range []profileSurfaces{profileSurfaceHooks, profileSurfaceInspect, profileSurfacesAll} {
			request := withGuardrailProfile(withProfileSurface(ctx, surface), set, "codex")
			resolved := resolvedGuardrailProfileFrom(request)
			if resolved == nil || !config.IsProfileMeet(resolved.decision.Name) {
				t.Fatalf("surface %v: no meet resolved", surface)
			}
			meet := snapshotRulePackGenerationFor(request, "codex")
			if got := len(meet.semanticRules); got != 300 {
				t.Errorf("surface %v: the meet has %d semantic rules; want both members' 300", surface, got)
			}
			if blocks, findings := blocksText(resolved.derived, meet, "codex", "action", provenanceToken("MEETCAP-SMALL-SECRET")); !blocks {
				t.Errorf("surface %v: the smaller pack's CRITICAL rule is not blocked (findings %v)", surface, FindingStrings(findings))
			}
		}
	}
}
