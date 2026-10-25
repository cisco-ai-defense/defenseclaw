// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// meetPathGeneration has prefix's HIGH plain marker rule and a MEDIUM one.
func meetPathGeneration(t *testing.T, prefix string) *compiledRulePackCategories {
	t.Helper()
	compiled, err := compileRulePackGeneration([]ruleCategory{{Name: "secret", Rules: []PatternRule{
		{ID: prefix + "-PLAIN", Title: prefix + " plain marker", Pattern: regexp.MustCompile(regexp.QuoteMeta(meetPlainMarker(prefix))),
			Severity: "HIGH", Confidence: 0.99},
		{ID: prefix + "-MED", Title: prefix + " medium marker", Pattern: regexp.MustCompile(regexp.QuoteMeta(meetMediumMarker(prefix))),
			Severity: "MEDIUM", Confidence: 0.99},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	return compiled
}

func meetMediumMarker(prefix string) string {
	return strings.ToLower(strings.ReplaceAll(prefix, "-", "_")) + "_medium_marker"
}

// A strictest combination enforces each member in its own mode on each
// request path. Profile a sets no mode, so it inherits the machine's: in
// "hook only" the Codex hook acts and inspect observes, in "inspect only"
// inspect acts and the Codex hook observes. It blocks from MEDIUM with a
// HILT from LOW and its own pack. Profile b sets action (both paths), blocks
// from HIGH with another pack. On a path where a only observes, the meet is
// b alone there: b's rules, b's level, b's HILT (none), so an a-only rule or
// a MEDIUM finding of b's never blocks there. On a path where both act, it
// is the strictest of both. Checked for the hook route, the inspect route,
// the LLM proxy, in both assignment orders (b first is the order of the
// review's case), and for an uncertain profile that a path's meet does not
// cover (loop round 2, continuation 3).
func TestMeetEnforcesEachMemberInItsOwnModeOnEachPath(t *testing.T) {
	stubProfileSources(t)
	for _, setup := range []struct {
		name               string
		baseMode, hookMode string
		aHook, aInspect    bool
	}{
		{name: "hook only", baseMode: "observe", hookMode: "action", aHook: true},
		{name: "inspect only", baseMode: "action", hookMode: "observe", aInspect: true},
	} {
		for _, first := range []string{"b", "a"} {
			t.Run(setup.name+"/"+first+" first", func(t *testing.T) {
				root := t.TempDir()
				cfg := &config.Config{}
				cfg.Guardrail.Mode = setup.baseMode
				cfg.Guardrail.Connector = "codex"
				cfg.Codex.Mode = setup.hookMode
				cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
					"a": {BlockAt: "MEDIUM", HILT: &config.HILTConfig{Enabled: true, MinSeverity: "LOW"}, RulePackDir: meetRulePackDir(t, root, "PATH-A")},
					"b": {Mode: "action", BlockAt: "HIGH", RulePackDir: meetRulePackDir(t, root, "PATH-B")},
				}
				p := identityTestPlatforms[0]
				byUser := config.ProfileAssignment{Profile: first, Match: config.ProfileMatch{Users: []string{p.id}}}
				second := map[string]string{"a": "b", "b": "a"}[first]
				byGroup := config.ProfileAssignment{Profile: second, Match: config.ProfileMatch{Groups: []string{p.group}}}
				cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{byUser, byGroup}
				set, err := newGuardrailProfileSet(cfg, nil, true)
				if err != nil {
					t.Fatal(err)
				}
				for _, scope := range []string{"", "codex"} {
					set.rules[effectiveRulePackKey(set.profiles["a"].Config, scope)] = meetPathGeneration(t, "PATH-A")
					set.rules[effectiveRulePackKey(set.profiles["b"].Config, scope)] = meetPathGeneration(t, "PATH-B")
				}
				set.missing = nil
				if aCfg := set.profileConfig("a"); configBlocksOn(aCfg, "codex", profilePathHook) != setup.aHook ||
					configBlocksOn(aCfg, "codex", profilePathInspect) != setup.aInspect {
					t.Fatalf("fixture: a blocks on hook %v, inspect %v", configBlocksOn(aCfg, "codex", profilePathHook), configBlocksOn(aCfg, "codex", profilePathInspect))
				}
				api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
				api.guardrailProfiles.set.Store(set)
				subject := context.WithValue(t.Context(), testVerifiedSubjectKey{}, identityTestSubject(p, p.providers[0], stateProven, true))
				// Requests pin the profile generation before scanning. Keep this
				// test's profile set independent of another test's process-wide
				// live set (as meetOfTwoAssignments does).
				subject = withPinnedGeneration(subject, &Generation{N: 1, Config: cfg, Profiles: set})
				meetName := config.ProfileMeetName([]string{"a", "b"})

				for _, path := range []struct {
					name  string
					ctx   context.Context
					aActs bool
				}{
					{"hook", api.withGuardrailProfileDecision(withProfilePath(subject, profilePathHook), "codex"), setup.aHook},
					// The inspect middleware's scope for an unscoped tool inspect.
					{"inspect", api.withGuardrailProfileDecision(context.WithValue(subject, profileRuleScanConnectorKey{}, "codex"), ""), setup.aInspect},
				} {
					resolved := resolvedGuardrailProfileFrom(path.ctx)
					if resolved == nil || resolved.decision.Name != meetName || resolved.decision.Refused != "" {
						t.Fatalf("%s: decision %+v; want the meet of a and b", path.name, resolved)
					}
					wantBlock, wantHILT := "HIGH", false
					if path.aActs {
						wantBlock, wantHILT = "MEDIUM", true
					}
					if got := resolveThresholds(resolved.derived, "codex").Block; got != wantBlock {
						t.Errorf("%s: blocks from %s; want %s", path.name, got, wantBlock)
					}
					if got := hiltEnabledForConfig(resolved.derived, "codex"); got != wantHILT {
						t.Errorf("%s: HILT %v; want %v", path.name, got, wantHILT)
					}
					if mode := map[string]string{"hook": resolved.derived.HookModeForConnector("codex"), "inspect": inspectMode(resolved.derived, "codex")}[path.name]; mode != "action" {
						t.Errorf("%s: mode %s; want action (b acts on both paths)", path.name, mode)
					}
					for _, rule := range []struct {
						prefix string
						want   bool
					}{{"PATH-A", path.aActs}, {"PATH-B", true}} {
						got := findingWithID(scanAllRulesForConnectorFor(path.ctx, "codex", meetPlainMarker(rule.prefix), "message"), rule.prefix+"-PLAIN")
						if (got != nil) != rule.want {
							t.Errorf("%s: %s finding %+v; want one %v", path.name, rule.prefix, got, rule.want)
						}
					}
				}

				// The real inspect route: an a-only rule and a MEDIUM finding of
				// b's block only where a acts on inspect.
				for _, content := range []struct {
					text  string
					block bool
				}{
					{meetPlainMarker("PATH-A"), setup.aInspect},
					{meetMediumMarker("PATH-B"), setup.aInspect},
					{meetPlainMarker("PATH-B"), true},
				} {
					body := fmt.Sprintf(`{"tool":"message","content":"%s"}`, content.text)
					req := httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool", strings.NewReader(body)).WithContext(subject)
					rec := httptest.NewRecorder()
					api.guardrailProfileInspectMiddleware(http.HandlerFunc(api.handleInspectTool)).ServeHTTP(rec, req)
					if got := strings.Contains(rec.Body.String(), `"action":"block"`); rec.Code != http.StatusOK || got != content.block {
						t.Errorf("inspect %s: %d %s; want block %v", content.text, rec.Code, rec.Body.String(), content.block)
					}
				}

				// The real Codex hook route, likewise where a acts on hooks.
				for _, content := range []struct {
					text  string
					block bool
				}{
					{meetPlainMarker("PATH-A"), setup.aHook},
					{meetMediumMarker("PATH-B"), setup.aHook},
					{meetPlainMarker("PATH-B"), true},
				} {
					body := fmt.Sprintf(`{"session_id":"path-session","hook_event_name":"UserPromptSubmit","prompt":"%s"}`, content.text)
					req := httptest.NewRequest(http.MethodPost, "/api/v1/codex/hook", strings.NewReader(body)).WithContext(subject)
					setTestCodexHookBinding(req, "UserPromptSubmit", defaultTestCodexHookContract)
					rec := httptest.NewRecorder()
					api.handleAgentHook("codex").ServeHTTP(rec, req)
					if got := strings.HasPrefix(rec.Body.String(), `{"action":"block"`); rec.Code != http.StatusOK || got != content.block {
						t.Errorf("hook %s: %d %.400s; want block %v", content.text, rec.Code, rec.Body.String(), content.block)
					}
				}

				// The LLM proxy decides by the inspect mode: its levels and HILT
				// are the inspect path's.
				previous := liveGuardrailProfiles.Load()
				liveGuardrailProfiles.Store(set)
				t.Cleanup(func() { liveGuardrailProfiles.Store(previous) })
				proxy := &GuardrailProxy{cfg: &config.GuardrailConfig{Connector: "codex"}, gatewayToken: "owner-token"}
				pinned := withPinnedGeneration(subject, &Generation{N: 1, Config: cfg, Profiles: set})
				req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil).WithContext(pinned)
				req.Header.Set("X-DC-Auth", "Bearer owner-token")
				proxyCtx := withThresholdConnector(proxy.withProxyAgent(req).Context(), "codex")
				resolved := proxyProfileFor(proxyCtx)
				if resolved == nil || resolved.decision.Name != meetName {
					t.Fatalf("proxy: decision %+v; want the meet", resolved)
				}
				wantBlock := "HIGH"
				if setup.aInspect {
					wantBlock = "MEDIUM"
				}
				wantRank, _ := guardrailThresholdRanks(ResolvedThresholds{Block: wantBlock, Alert: "LOW"})
				if got := requestThresholds(proxyCtx); got.Block != wantRank {
					t.Errorf("proxy: block rank %d; want %d (%s)", got.Block, wantRank, wantBlock)
				}
				if got := hiltEnabledForConfig(resolved.derived, "codex"); got != setup.aInspect {
					t.Errorf("proxy: HILT %v; want %v", got, setup.aInspect)
				}
			})
		}
	}
}

// A proven meet covers an uncertain profile only on each path with what it
// decides that path with. In "hook only", a acts on the Codex hook from LOW
// and b on both paths from HIGH; c, uncertain, acts on both from MEDIUM, on
// b's pack. The meet blocks from LOW on the hook but from HIGH on inspect,
// so it does not cover c on inspect: the decision keeps c's missing fact
// (refused) or enforces c's MEDIUM level on inspect, never HIGH.
func TestProvenMeetCoversAnUncertainProfileOnEachPath(t *testing.T) {
	stubProfileSources(t)
	root := t.TempDir()
	pack := meetRulePackDir(t, root, "COVER-B")
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Connector = "codex"
	cfg.Codex.Mode = "action"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"a": {BlockAt: "LOW", RulePackDir: pack},
		"b": {Mode: "action", BlockAt: "HIGH", RulePackDir: pack},
		"c": {Mode: "action", BlockAt: "MEDIUM", RulePackDir: pack},
	}
	p := identityTestPlatforms[0]
	byName := config.ProfileAssignment{Profile: "c", Match: config.ProfileMatch{Users: []string{`.\` + p.name}}}
	byGroup := config.ProfileAssignment{Profile: "a", Match: config.ProfileMatch{Groups: []string{p.group}}}
	byUID := config.ProfileAssignment{Profile: "b", Match: config.ProfileMatch{Users: []string{p.id}}}
	for _, order := range [][]config.ProfileAssignment{{byName, byGroup, byUID}, {byGroup, byUID, byName}} {
		t.Run(order[0].Profile+" first", func(t *testing.T) {
			cfg.Guardrail.ProfileAssignments = order
			set := newGuardrailProfileSetFor(t, cfg)
			subject := identityTestSubject(p, p.providers[0], stateProven, true)
			subject.holderUnproven = true
			api := &APIServer{scannerCfg: cfg}
			api.guardrailProfiles.set.Store(set)
			base := context.WithValue(t.Context(), testVerifiedSubjectKey{}, subject)
			for _, path := range []struct {
				name string
				ctx  context.Context
			}{
				{"hook", api.withGuardrailProfileDecision(withProfilePath(base, profilePathHook), "codex")},
				{"inspect", api.withGuardrailProfileDecision(context.WithValue(base, profileRuleScanConnectorKey{}, "codex"), "")},
			} {
				resolved := resolvedGuardrailProfileFrom(path.ctx)
				if resolved == nil {
					t.Fatalf("%s: no decision", path.name)
				}
				if resolved.decision.Refused != "" {
					if !slices.Contains(resolved.decision.Unproven, "account:unknown") {
						t.Fatalf("%s: refusal %+v does not keep the missing account fact", path.name, resolved.decision)
					}
					continue
				}
				if block := resolveThresholds(resolved.derived, "codex").Block; block != "LOW" && block != "MEDIUM" {
					t.Fatalf("%s: decision %+v blocks from %s; c may apply and blocks from MEDIUM", path.name, resolved.decision, block)
				}
			}
		})
	}
}

// meetBudgetGeneration has count semantic rules prefix-NNN that all match
// `echo hi`, each with its own expression; shared rules (the same
// definition in every pack that has them) are listed first.
func meetBudgetGeneration(t *testing.T, prefix string, count int, shared int) *compiledRulePackCategories {
	t.Helper()
	category := ruleCategory{Name: "command"}
	rule := func(id string) PatternRule {
		return PatternRule{ID: id, Title: id, Pattern: regexp.MustCompile(regexp.QuoteMeta(strings.ToLower(id) + "_marker")),
			Expression: "f.commands.exists(c, c.program == 'echo') && '" + id + "' != ''",
			Severity:   "HIGH", Confidence: 0.99, ToolCallOnly: true}
	}
	for i := range shared {
		category.Rules = append(category.Rules, rule(fmt.Sprintf("BUD-S-%03d", i)))
	}
	for i := range count {
		category.Rules = append(category.Rules, rule(fmt.Sprintf("%s-%03d", prefix, i)))
	}
	compiled, err := compileRulePackGeneration([]ruleCategory{category})
	if err != nil {
		t.Fatal(err)
	}
	return compiled
}

// budgetFindings counts the enforcing findings of rules prefix-NNN.
func budgetFindings(findings []RuleFinding, prefix string) int {
	n := 0
	for _, finding := range findings {
		if strings.HasPrefix(finding.RuleID, prefix+"-") && finding.contributesToEnforcement() {
			n++
		}
	}
	return n
}

// A strictest combination judges one action within the one semantic cost
// budget a single profile has (trustedActionDispatchMaxCost), on the call
// and on each promoted artifact: the members share it, so overlapping
// profiles do not multiply the work. An expression several members have is
// judged once, so where packs overlap every rule still runs within the
// budget one member needs (loop round 2, continuation 3).
func TestMeetJudgesOneActionWithinOneSemanticBudget(t *testing.T) {
	stubProfileSources(t)
	const command = "echo hi"
	call := trustedActionRequest{Input: actionfacts.Input{Tool: "shell", Command: command, CWD: "/repo"},
		LegacyText: command, Connector: "codex", EnforcementCapable: true}
	// alone is the cost and findings of generation g alone, as one profile.
	alone := func(g *compiledRulePackCategories) (uint64, []RuleFinding) {
		request := call
		request.generation, request.budget = g, newTrustedActionBudget(false)
		findings := dispatchTrustedAction(t.Context(), request)
		return request.budget.consumed, findings
	}
	meetCtx := func(t *testing.T, a, b *compiledRulePackCategories) context.Context {
		root := t.TempDir()
		profiles := map[string]config.GuardrailProfile{
			"a": {Mode: "action", BlockAt: "HIGH", RulePackDir: meetRulePackDir(t, root, "BUD-A")},
			"b": {Mode: "action", BlockAt: "HIGH", RulePackDir: meetRulePackDir(t, root, "BUD-B")},
		}
		set, _ := meetOfTwoAssignments(t, "action", profiles, "a", "b", "codex")
		set.rules[effectiveRulePackKey(set.profiles["a"].Config, "codex")] = a
		set.rules[effectiveRulePackKey(set.profiles["b"].Config, "codex")] = b
		set.missing = nil
		ctx := meetFixtureContext(t, set, "codex")
		if g := snapshotRulePackGenerationFor(ctx, "codex"); g == nil || len(g.members) != 2 {
			t.Fatal("fixture: the meet does not judge with both members' generations")
		}
		return ctx
	}
	limit := func(t *testing.T, cost uint64) {
		previous := trustedActionDispatchMaxCost
		trustedActionDispatchMaxCost = cost
		t.Cleanup(func() { trustedActionDispatchMaxCost = previous })
	}

	t.Run("distinct packs share one budget", func(t *testing.T) {
		a, b := meetBudgetGeneration(t, "BUD-A", 30, 0), meetBudgetGeneration(t, "BUD-B", 30, 0)
		costA, findingsA := alone(a)
		costB, findingsB := alone(b)
		if budgetFindings(findingsA, "BUD-A") != 30 || budgetFindings(findingsB, "BUD-B") != 30 || costA == 0 || costB == 0 {
			t.Fatalf("fixture: alone a %d findings (cost %d), b %d (cost %d)", budgetFindings(findingsA, "BUD-A"), costA, budgetFindings(findingsB, "BUD-B"), costB)
		}
		t.Logf("one action alone: a costs %d, b costs %d", costA, costB)
		// Each member alone fits; both together do not.
		limit(t, max(costA, costB))
		ctx := meetCtx(t, a, b)
		budget := newTrustedActionBudget(true)
		request := call
		request.budget = budget
		findings := dispatchTrustedAction(ctx, request)
		if budget.consumed > trustedActionDispatchMaxCost || budget.consumed < costA || !budget.reached {
			t.Fatalf("meet cost %d (reached %v); want the first member's %d at least and one budget (%d) at most", budget.consumed, budget.reached, costA, trustedActionDispatchMaxCost)
		}
		if got := budgetFindings(findings, "BUD-A"); got != 30 {
			t.Fatalf("meet: %d of a's findings; want all 30 within the budget", got)
		}
		// Without a caller's budget the meet makes one, as one profile does.
		findings = dispatchTrustedAction(ctx, call)
		if got := budgetFindings(findings, "BUD-A") + budgetFindings(findings, "BUD-B"); got >= 60 {
			t.Fatalf("meet judged %d semantic findings; the members' work together must fit one action's budget", got)
		}
		// A promoted artifact is one action too.
		t.Run("promoted artifact", func(t *testing.T) {
			requireNativePOSIXArtifactHost(t)
			dir := t.TempDir()
			script := filepath.Join(dir, "echo.sh")
			if err := os.WriteFile(script, []byte("#!/bin/sh\necho hi\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			facts := actionfacts.Analyze(actionfacts.Input{Tool: "shell", Command: fmt.Sprintf("bash %q", script), CWD: dir})
			artifact := promotedArtifactFindings(ctx, agentHookRequest{ConnectorName: "codex"}, facts, true, nil)
			if got := budgetFindings(artifact, "BUD-A") + budgetFindings(artifact, "BUD-B"); got == 0 || got >= 60 {
				t.Fatalf("promoted artifact: %d semantic findings; want the members' work within one budget", got)
			}
		})
	})

	t.Run("overlapping packs judge a shared expression once", func(t *testing.T) {
		// b is a's 30 rules and one of its own; b alone needs every rule's cost.
		a, b := meetBudgetGeneration(t, "BUD-A", 0, 30), meetBudgetGeneration(t, "BUD-B", 1, 30)
		costA, _ := alone(a)
		costB, findingsB := alone(b)
		if budgetFindings(findingsB, "BUD-S") != 30 || budgetFindings(findingsB, "BUD-B") != 1 || costB <= costA {
			t.Fatalf("fixture: b alone %d shared + %d own findings, cost %d (a %d)", budgetFindings(findingsB, "BUD-S"), budgetFindings(findingsB, "BUD-B"), costB, costA)
		}
		limit(t, costB)
		ctx := meetCtx(t, a, b)
		budget := newTrustedActionBudget(true)
		request := call
		request.budget = budget
		findings := dispatchTrustedAction(ctx, request)
		if budget.consumed != costB {
			t.Errorf("meet cost %d; want b's alone (%d): each shared expression judged once", budget.consumed, costB)
		}
		if budgetFindings(findings, "BUD-S") != 30 || budgetFindings(findings, "BUD-B") != 1 {
			t.Fatalf("meet: %d shared + %d own findings; want every rule of both members", budgetFindings(findings, "BUD-S"), budgetFindings(findings, "BUD-B"))
		}
	})
}
