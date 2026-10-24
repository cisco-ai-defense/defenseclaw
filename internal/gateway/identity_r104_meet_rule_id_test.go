// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// meetOfTwoAssignments is a set whose proven account has profile first by
// user and second by group, with profiles, and ctx resolved on it for scope.
func meetOfTwoAssignments(t *testing.T, mode string, profiles map[string]config.GuardrailProfile, first, second, scope string) (*guardrailProfileSet, context.Context) {
	t.Helper()
	cfg := &config.Config{}
	cfg.Guardrail.Mode = mode
	cfg.Guardrail.Profiles = profiles
	p := identityTestPlatforms[0]
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
		{Profile: first, Match: config.ProfileMatch{Users: []string{p.id}}},
		{Profile: second, Match: config.ProfileMatch{Groups: []string{p.group}}},
	}
	set, err := newGuardrailProfileSet(cfg, nil, true)
	if err != nil || set == nil {
		t.Fatalf("profile set: %v", err)
	}
	ctx := context.WithValue(t.Context(), testVerifiedSubjectKey{}, identityTestSubject(p, p.providers[0], stateProven, true))
	return set, withGuardrailProfile(ctx, set, scope)
}

// The shipped default and strict packs both define ENT-EMAIL-BULK, at LOW
// and MEDIUM. The meet of two proven profiles that block at MEDIUM with
// them flags an e-mail address at MEDIUM, as the strict profile alone
// does, whichever profile's name sorts first.
func TestShippedPackMeetKeepsTheStrictDefinitionOfASharedRuleID(t *testing.T) {
	stubProfileSources(t)
	root := guardrailPoliciesRoot(t)
	const text = "send the quarterly report to dana.reyes@contoso-mail.net today"
	for _, order := range [][2]string{{"a-default", "b-strict"}, {"b-default", "a-strict"}} {
		t.Run(order[0], func(t *testing.T) {
			profiles := map[string]config.GuardrailProfile{
				order[0]: {Mode: "action", BlockAt: "MEDIUM", RulePackDir: filepath.Join(root, "default")},
				order[1]: {Mode: "action", BlockAt: "MEDIUM", RulePackDir: filepath.Join(root, "strict")},
			}
			_, strictCtx := meetOfTwoAssignments(t, "observe", profiles, order[1], order[1], "codex")
			if name := resolvedGuardrailProfileFrom(strictCtx).decision.Name; name != order[1] {
				t.Fatalf("strict-only decision %q", name)
			}
			want := findingWithID(scanContentRulesForConnectorFor(strictCtx, "codex", text, "message", ruleContentScopeUntrusted), "ENT-EMAIL-BULK")
			if want == nil || want.Severity != "MEDIUM" {
				t.Fatalf("strict profile alone: ENT-EMAIL-BULK %+v; want MEDIUM", want)
			}
			_, ctx := meetOfTwoAssignments(t, "observe", profiles, order[0], order[1], "codex")
			decision := resolvedGuardrailProfileFrom(ctx).decision
			if !config.IsProfileMeet(decision.Name) || decision.Refused != "" {
				t.Fatalf("decision %+v; want the meet of both profiles", decision)
			}
			got := findingWithID(scanContentRulesForConnectorFor(ctx, "codex", text, "message", ruleContentScopeUntrusted), "ENT-EMAIL-BULK")
			if got == nil || got.Severity != "MEDIUM" {
				t.Fatalf("meet: ENT-EMAIL-BULK %+v; want the strict pack's MEDIUM", got)
			}
		})
	}
}

// Two members define one rule ID differently. Each member's definition
// applies as that member scans it, whichever comes first: a weaker match
// of one never hides a stronger match of the other, on raw or on
// shell-normalized text.
func TestMeetScansEachDefinitionOfACollidingRuleID(t *testing.T) {
	generation := func(rules ...PatternRule) *compiledRulePackCategories {
		compiled, err := compileRulePackGeneration([]ruleCategory{{Name: "secret", Rules: rules}})
		if err != nil {
			t.Fatal(err)
		}
		return compiled
	}
	rule := func(pattern, severity string) PatternRule {
		return PatternRule{ID: "R-SHARED", Pattern: regexp.MustCompile(pattern), Title: "shared", Severity: severity, Confidence: 0.9}
	}
	for _, tc := range []struct {
		name         string
		weak, strong PatternRule
		text         string
	}{
		{name: "both match", weak: rule(`token`, "LOW"), strong: rule(`token-[0-9]+`, "HIGH"), text: "token-42"},
		{name: "stronger only on normalized text", weak: rule(`sha`, "LOW"), strong: rule(`/etc/shadow`, "HIGH"), text: `cat /etc/sha""dow`},
		{name: "same pattern", weak: rule(`token`, "LOW"), strong: rule(`token`, "HIGH"), text: "token"},
	} {
		for _, order := range []string{"weak first", "strong first"} {
			t.Run(tc.name+"/"+order, func(t *testing.T) {
				sources := []*compiledRulePackCategories{generation(tc.weak), generation(tc.strong)}
				if order == "strong first" {
					sources[0], sources[1] = sources[1], sources[0]
				}
				merged, err := mergeRuleGenerations(sources)
				if err != nil {
					t.Fatal(err)
				}
				got := findingWithID(scanRuleGeneration(merged, tc.text, "Bash", ruleScanOptions{}), "R-SHARED")
				if got == nil || got.Severity != "HIGH" {
					t.Fatalf("finding %+v; want the stronger member's HIGH", got)
				}
			})
		}
	}
}

// Two members' semantic rules share an ID with different expressions. The
// meet judges a tool call with each member's own expression: the call only
// the second member's expression matches is flagged at its severity.
func TestMeetDispatchJudgesEachMembersExpressionOfASharedRuleID(t *testing.T) {
	stubProfileSources(t)
	semantic := func(program, severity string) *compiledRulePackCategories {
		compiled, err := compileRulePackGeneration([]ruleCategory{{Name: "command", Rules: []PatternRule{{
			ID: "MEET-SHARED-CMD", Title: "shared command", Pattern: regexp.MustCompile(`\b` + program + `\b`),
			Expression: "f.commands.exists(c, c.program == '" + program + "')",
			Severity:   severity, Confidence: 0.99, ToolCallOnly: true,
		}}}})
		if err != nil {
			t.Fatal(err)
		}
		return compiled
	}
	root := t.TempDir()
	for _, order := range [][2]string{{"a", "b"}, {"b", "a"}} {
		t.Run(order[0]+" echo", func(t *testing.T) {
			profiles := map[string]config.GuardrailProfile{
				"a": {Mode: "action", BlockAt: "MEDIUM", RulePackDir: meetRulePackDir(t, root, "SEM-A")},
				"b": {Mode: "action", BlockAt: "MEDIUM", RulePackDir: meetRulePackDir(t, root, "SEM-B")},
			}
			set, ctx := meetOfTwoAssignments(t, "observe", profiles, order[0], order[1], "codex")
			set.rules[effectiveRulePackKey(set.profiles[order[0]].Config, "codex")] = semantic("echo", "HIGH")
			set.rules[effectiveRulePackKey(set.profiles[order[1]].Config, "codex")] = semantic("printf", "MEDIUM")
			set.missing = nil
			if decision := resolvedGuardrailProfileFrom(ctx).decision; !config.IsProfileMeet(decision.Name) || decision.Refused != "" {
				t.Fatalf("decision %+v; want the meet", decision)
			}
			for _, tc := range []struct{ command, severity string }{{"echo hi", "HIGH"}, {"printf hi", "MEDIUM"}} {
				findings := dispatchTrustedAction(ctx, trustedActionRequest{
					Input:      actionfacts.Input{Tool: "shell", Command: tc.command, CWD: "/repo"},
					LegacyText: tc.command, Connector: "codex", EnforcementCapable: true,
				})
				got := findingWithID(findings, "MEET-SHARED-CMD")
				if got == nil || got.Severity != tc.severity || !got.contributesToEnforcement() {
					t.Fatalf("%q: finding %+v; want an enforcing %s finding from its member's expression", tc.command, got, tc.severity)
				}
			}
		})
	}
}

// Two proven observe profiles with different sandbox sections form a meet.
// Each pack is valid alone; their union is over the semantic rule limit of
// one generation. No member blocks, so the meet observes with each
// member's rules and never refuses; where both block, the uncompiled
// merge still refuses.
func TestObserveOnlyMeetOverTheRuleLimitObservesInsteadOfRefusing(t *testing.T) {
	stubProfileSources(t)
	root := t.TempDir()
	aRules, bRules := meetSemanticGeneration(t, "OBS-A", 200), meetSemanticGeneration(t, "OBS-B", 200)
	if _, err := mergeRuleGenerations([]*compiledRulePackCategories{aRules, bRules}); err == nil {
		t.Fatal("fixture unexpectedly fits in one compiled generation")
	}
	for _, tc := range []struct {
		name         string
		aMode, bMode string
		wantRefused  bool
	}{
		{name: "both observe", aMode: "observe", bMode: "observe"},
		// Only a's rules are scanned where only a blocks: no merge.
		{name: "one member blocks", aMode: "action", bMode: "observe"},
		{name: "both block", aMode: "action", bMode: "action", wantRefused: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			profiles := map[string]config.GuardrailProfile{
				"a": {Mode: tc.aMode, BlockAt: "HIGH", RulePackDir: meetRulePackDir(t, root, "OBS-A"),
					Sandbox: &config.OpenShellAdminConfig{EgressBlock: []string{"a.example"}}},
				"b": {Mode: tc.bMode, BlockAt: "HIGH", RulePackDir: meetRulePackDir(t, root, "OBS-B"),
					Sandbox: &config.OpenShellAdminConfig{EgressBlock: []string{"b.example"}}},
			}
			set, ctx := meetOfTwoAssignments(t, "observe", profiles, "a", "b", "codex")
			set.rules[effectiveRulePackKey(set.profiles["a"].Config, "codex")] = aRules
			set.rules[effectiveRulePackKey(set.profiles["b"].Config, "codex")] = bRules
			set.missing = nil
			// Resolve again now that the fixture packs are in place.
			ctx = withGuardrailProfile(context.WithValue(t.Context(), testVerifiedSubjectKey{},
				identityTestSubject(identityTestPlatforms[0], identityTestPlatforms[0].providers[0], stateProven, true)), set, "codex")
			decision := resolvedGuardrailProfileFrom(ctx).decision
			if decision.Name != config.ProfileMeetName([]string{"a", "b"}) {
				t.Fatalf("decision %+v; want the meet of both profiles", decision)
			}
			if (decision.Refused != "") != tc.wantRefused {
				t.Fatalf("decision %+v; want refused %v", decision, tc.wantRefused)
			}
			api := &APIServer{}
			api.guardrailProfiles.set.Store(set)
			response, refused := api.refuseProfileHook(ctx, connector.HookProfile{}, "codex",
				agentHookRequest{ConnectorName: "codex", HookEventName: "pre_tool_use"}, nil, nil)
			if refused != tc.wantRefused || (refused && response.Action != "block") {
				t.Fatalf("hook refused %v (%+v); want %v", refused, response, tc.wantRefused)
			}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool", nil).WithContext(ctx)
			if got := api.refuseProfileInspect(httptest.NewRecorder(), req, "/api/v1/inspect/tool", "inspect-tool-block", "tool"); got != tc.wantRefused {
				t.Fatalf("inspect refused %v; want %v", got, tc.wantRefused)
			}
			if got := refuseProfileProxy(httptest.NewRecorder(), req); got != tc.wantRefused {
				t.Fatalf("proxy refused %v; want %v", got, tc.wantRefused)
			}
			if tc.bMode != "observe" || tc.aMode != "observe" {
				return
			}
			// The meet still observes with every rule of both members.
			generation, err := set.meet(decision.Name).ruleGeneration(ctx, set, "codex")
			if err != nil || generation == nil {
				t.Fatalf("observe-only meet generation %p, error %v", generation, err)
			}
			for _, marker := range []string{"OBS-A-marker-000", "OBS-B-marker-199"} {
				findings := scanRuleGeneration(generation, marker, "Bash", ruleScanOptions{includeToolCallOnly: true})
				if len(findings) == 0 {
					t.Fatalf("%s: no finding; want the member's rule observed", marker)
				}
			}
		})
	}
}
