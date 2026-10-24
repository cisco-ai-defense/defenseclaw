// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/agentidentity"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

func meetSemanticGeneration(t *testing.T, prefix string, count int) *compiledRulePackCategories {
	t.Helper()
	category := ruleCategory{Name: "command"}
	for i := range count {
		marker := fmt.Sprintf("%s-marker-%03d", prefix, i)
		category.Rules = append(category.Rules, PatternRule{
			ID: prefix + fmt.Sprintf("-%03d", i), Title: marker,
			Pattern:    regexp.MustCompile(regexp.QuoteMeta(marker)),
			Expression: "f.commands.exists(c, c.program == 'echo')",
			Severity:   "HIGH", Confidence: 0.99, ToolCallOnly: true,
		})
	}
	compiled, err := compileRulePackGeneration([]ruleCategory{category})
	if err != nil {
		t.Fatalf("compile %s: %v", prefix, err)
	}
	return compiled
}

func meetRulePackDir(t *testing.T, root, name string) string {
	t.Helper()
	dir := filepath.Join(root, name)
	writeRulePackFixtureFile(t, dir, "rules/marker.yaml", fmt.Sprintf(`version: 1
category: secret
rules:
  - id: %s-FIXTURE
    pattern: "%s_fixture_marker"
    title: %s fixture
    severity: HIGH
    confidence: 0.99
    tags: [test]
`, name, name, name))
	return dir
}

// Every member pack is valid alone, but their union exceeds the semantic
// generation limit. The first member's blocking rule must never disappear
// just because the second member has more rules.
func TestOverLimitProfileMeetRefusesInsteadOfDroppingAMember(t *testing.T) {
	stubProfileSources(t)
	aRules := meetSemanticGeneration(t, "MEET-A", 2)
	bRules := meetSemanticGeneration(t, "MEET-B", maxGenerationSemanticRules-1)
	root := t.TempDir()
	writeRulePackFixtureFile(t, filepath.Join(root, "a"), "rules/a.yaml", `version: 1
category: secret
rules:
  - id: MEET-A-FIXTURE
    pattern: "meet_a_fixture"
    title: first member fixture
    severity: HIGH
    confidence: 0.99
    tags: [test]
`)
	writeRulePackFixtureFile(t, filepath.Join(root, "b"), "rules/b.yaml", `version: 1
category: secret
rules:
  - id: MEET-B-FIXTURE
    pattern: "meet_b_fixture"
    title: second member fixture
    severity: HIGH
    confidence: 0.99
    tags: [test]
`)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"a": {Mode: "action", BlockAt: "HIGH", RulePackDir: filepath.Join(root, "a")},
		"b": {Mode: "action", BlockAt: "HIGH", RulePackDir: filepath.Join(root, "b")},
	}
	p := identityTestPlatforms[0]
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
		{Profile: "a", Match: config.ProfileMatch{Users: []string{p.id}}},
		{Profile: "b", Match: config.ProfileMatch{Groups: []string{p.group}}},
	}
	set, err := newGuardrailProfileSet(cfg, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	set.rules[effectiveRulePackKey(set.profiles["a"].Config, "codex")] = aRules
	set.rules[effectiveRulePackKey(set.profiles["b"].Config, "codex")] = bRules
	set.missing = nil
	if _, err := mergeRuleGenerations([]*compiledRulePackCategories{aRules, bRules}); err == nil {
		t.Fatal("fixture unexpectedly fits in one compiled generation")
	}
	subject := identityTestSubject(p, p.providers[0], stateProven, true)
	ctx := context.WithValue(t.Context(), testVerifiedSubjectKey{}, subject)
	ctx = withGuardrailProfile(ctx, set, "codex")
	decision := resolvedGuardrailProfileFrom(ctx).decision
	if decision.Name != config.ProfileMeetName([]string{"a", "b"}) || decision.Refused == "" ||
		!strings.Contains(decision.Refused, "rule packs") {
		t.Fatalf("over-limit meet decision = %+v; want a refusal naming the pack merge", decision)
	}
	meet := set.meet(decision.Name)
	if generation, err := meet.ruleGeneration(ctx, set, "codex"); err == nil || generation != nil {
		t.Fatalf("failed meet returned generation %p, error %v; want no member substitution", generation, err)
	}
	api := &APIServer{}
	api.guardrailProfiles.set.Store(set)
	if response, refused := api.refuseProfileHook(ctx, connector.HookProfile{}, "codex",
		agentHookRequest{ConnectorName: "codex", HookEventName: "pre_tool_use"}, nil, nil); !refused || response.Action != "block" {
		t.Fatalf("hook did not refuse the uncompiled meet: %+v, refused=%v", response, refused)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	if !api.refuseProfileInspect(rec, req, "/api/v1/inspect/tool", "inspect-tool-block", "tool") ||
		!strings.Contains(rec.Body.String(), `"action":"block"`) {
		t.Fatalf("inspect did not refuse the uncompiled meet: %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	if !refuseProfileProxy(rec, req) || rec.Code != http.StatusForbidden {
		t.Fatalf("proxy did not refuse the uncompiled meet: %d %s", rec.Code, rec.Body.String())
	}
}

// An unscoped tool inspect scans the gateway's Codex connector, even when
// the credential itself names no connector. Its Codex merge must compile.
func TestOverLimitConnectorMeetRefusesUnscopedInspect(t *testing.T) {
	stubProfileSources(t)
	root := t.TempDir()
	globalA, globalB := meetRulePackDir(t, root, "GLOBAL-A"), meetRulePackDir(t, root, "GLOBAL-B")
	codexA, codexB := meetRulePackDir(t, root, "CODEX-A"), meetRulePackDir(t, root, "CODEX-B")
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "codex"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"a": {Mode: "action", BlockAt: "HIGH", RulePackDir: globalA,
			Connectors: map[string]config.PerConnectorGuardrailConfig{"codex": {RulePackDir: codexA}}},
		"b": {Mode: "action", BlockAt: "HIGH", RulePackDir: globalB,
			Connectors: map[string]config.PerConnectorGuardrailConfig{"codex": {RulePackDir: codexB}}},
	}
	p := identityTestPlatforms[0]
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
		{Profile: "a", Match: config.ProfileMatch{Users: []string{p.id}}},
		{Profile: "b", Match: config.ProfileMatch{Groups: []string{p.group}}},
	}
	set, err := newGuardrailProfileSet(cfg, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	aRules := meetSemanticGeneration(t, "CODEX-A", 2)
	bRules := meetSemanticGeneration(t, "CODEX-B", maxGenerationSemanticRules-1)
	set.rules[effectiveRulePackKey(set.profiles["a"].Config, "codex")] = aRules
	set.rules[effectiveRulePackKey(set.profiles["b"].Config, "codex")] = bRules
	subject := identityTestSubject(p, p.providers[0], stateProven, true)
	ctx := context.WithValue(t.Context(), testVerifiedSubjectKey{}, subject)
	ctx = withGuardrailProfile(ctx, set, "")
	decision := resolvedGuardrailProfileFrom(ctx).decision
	if decision.Name != config.ProfileMeetName([]string{"a", "b"}) {
		t.Fatalf("decision = %+v; want a proven meet", decision)
	}
	meet := set.meet(decision.Name)
	if generation, err := meet.ruleGeneration(ctx, set, ""); err != nil || generation == nil {
		t.Fatalf("global meet did not compile: generation %p, error %v", generation, err)
	}
	if generation, err := meet.ruleGeneration(ctx, set, "codex"); err == nil || generation != nil {
		t.Fatalf("Codex meet unexpectedly compiled: generation %p, error %v", generation, err)
	}
	if decision.Refused == "" || !strings.Contains(decision.Refused, "rule packs") {
		t.Fatalf("unscoped decision did not refuse failed Codex merge: %+v", decision)
	}
	api := &APIServer{scannerCfg: cfg}
	api.guardrailProfiles.set.Store(set)
	if got := api.connectorName(); got != "codex" || authenticatedInspectConnector(ctx) != "" {
		t.Fatalf("inspect must resolve unscoped and scan Codex: gateway %q, authenticated %q", got, authenticatedInspectConnector(ctx))
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool",
		strings.NewReader(`{"tool":"message","content":"CODEX-A-marker-000"}`)).WithContext(ctx)
	rec := httptest.NewRecorder()
	api.guardrailProfileInspectMiddleware(http.HandlerFunc(api.handleInspectTool)).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"action":"block"`) ||
		!strings.Contains(rec.Body.String(), "rule packs") {
		t.Fatalf("unscoped inspect did not block: %d %s", rec.Code, rec.Body.String())
	}
}

func TestUnscopedInspectSelectsCodexMeetWhenGlobalProfilesDisagree(t *testing.T) {
	stubProfileSources(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "codex"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"a": {BlockAt: "LOW", Connectors: map[string]config.PerConnectorGuardrailConfig{"codex": {BlockAt: "CRITICAL"}}},
		"b": {BlockAt: "HIGH"},
	}
	p := identityTestPlatforms[0]
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
		{Profile: "b", Match: config.ProfileMatch{Users: []string{p.id}}},
		{Profile: "a", Match: config.ProfileMatch{Groups: []string{p.group}}},
	}
	set, err := newGuardrailProfileSet(cfg, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(t.Context(), testVerifiedSubjectKey{}, identityTestSubject(p, p.providers[0], stateProven, true))
	decision := resolvedGuardrailProfileFrom(withGuardrailProfile(ctx, set, "")).decision
	if decision.Refused != "" || decision.Name != config.ProfileMeetName([]string{"a", "b"}) {
		t.Fatalf("unscoped decision = %+v; want the proven meet", decision)
	}
	derived := set.profileConfig(decision.Name)
	if got := resolveThresholds(derived, "codex").Block; got != "HIGH" {
		t.Fatalf("Codex block threshold = %q, want HIGH from b", got)
	}
	if got := resolveThresholds(derived, "").Block; got != "LOW" {
		t.Fatalf("global block threshold = %q, want LOW from a", got)
	}
}

func TestCodexMeetIgnoresUnscannableClaudeMerge(t *testing.T) {
	stubProfileSources(t)
	root := t.TempDir()
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "codex"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"a": {RulePackDir: meetRulePackDir(t, root, "GLOBAL-A"), Connectors: map[string]config.PerConnectorGuardrailConfig{
			"codex":      {RulePackDir: meetRulePackDir(t, root, "CODEX-A")},
			"claudecode": {RulePackDir: meetRulePackDir(t, root, "CLAUDE-A")},
		}},
		"b": {RulePackDir: meetRulePackDir(t, root, "GLOBAL-B"), Connectors: map[string]config.PerConnectorGuardrailConfig{
			"codex":      {RulePackDir: meetRulePackDir(t, root, "CODEX-B")},
			"claudecode": {RulePackDir: meetRulePackDir(t, root, "CLAUDE-B")},
		}},
	}
	p := identityTestPlatforms[0]
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
		{Profile: "a", Match: config.ProfileMatch{Users: []string{p.id}}},
		{Profile: "b", Match: config.ProfileMatch{Groups: []string{p.group}}},
	}
	set, err := newGuardrailProfileSet(cfg, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	set.rules[effectiveRulePackKey(set.profiles["a"].Config, "claudecode")] = meetSemanticGeneration(t, "CLAUDE-A", 2)
	set.rules[effectiveRulePackKey(set.profiles["b"].Config, "claudecode")] = meetSemanticGeneration(t, "CLAUDE-B", maxGenerationSemanticRules-1)
	ctx := context.WithValue(t.Context(), testVerifiedSubjectKey{}, identityTestSubject(p, p.providers[0], stateProven, true))
	for _, scope := range []string{"codex", ""} {
		resolved := resolvedGuardrailProfileFrom(withGuardrailProfile(ctx, set, scope))
		if resolved.decision.Name != config.ProfileMeetName([]string{"a", "b"}) || resolved.decision.Refused != "" {
			t.Fatalf("scope %q decision = %+v; Codex merge is valid", scope, resolved.decision)
		}
		if _, err := set.meet(resolved.decision.Name).ruleGeneration(ctx, set, "codex"); err != nil {
			t.Fatalf("scope %q Codex merge: %v", scope, err)
		}
	}
	meet := set.meet(config.ProfileMeetName([]string{"a", "b"}))
	if _, err := meet.ruleGeneration(ctx, set, "claudecode"); err == nil {
		t.Fatal("Claude Code fixture unexpectedly compiled")
	}
	// A global merge failure is irrelevant to a Codex tool scan, but must
	// refuse an unscoped prompt scan, which reads the global generation.
	set.rules[effectiveRulePackKey(set.profiles["a"].Config, "")] = meetSemanticGeneration(t, "GLOBAL-A", 2)
	set.rules[effectiveRulePackKey(set.profiles["b"].Config, "")] = meetSemanticGeneration(t, "GLOBAL-B", maxGenerationSemanticRules-1)
	api := &APIServer{scannerCfg: cfg}
	api.guardrailProfiles.set.Store(set)
	for _, tc := range []struct {
		path        string
		wantRefused bool
	}{
		{path: "/api/v1/inspect/tool"},
		{path: "/api/v1/inspect/request", wantRefused: true},
	} {
		req := httptest.NewRequest(http.MethodPost, tc.path, nil).WithContext(ctx)
		handler := api.guardrailProfileInspectMiddleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			got := resolvedGuardrailProfileFrom(r.Context()).decision
			if (got.Refused != "") != tc.wantRefused {
				t.Errorf("%s decision = %+v; want refused %v", tc.path, got, tc.wantRefused)
			}
		}))
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}
}

func TestProfileMeetKeepsHookActionAndInspectObserveSeparate(t *testing.T) {
	stubProfileSources(t)
	root := t.TempDir()
	profiles := map[string]config.GuardrailProfile{
		"a": {RulePackDir: meetRulePackDir(t, root, "MODE-A")},
		"b": {RulePackDir: meetRulePackDir(t, root, "MODE-B")},
	}
	for _, tc := range []struct {
		name, guardrailMode, hookMode, wantAction string
		wantWouldBlock                            bool
	}{
		{name: "hook action", guardrailMode: "observe", hookMode: "action", wantAction: "allow", wantWouldBlock: true},
		{name: "inspect action", guardrailMode: "action", hookMode: "observe", wantAction: "block"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Guardrail.Mode = tc.guardrailMode
			cfg.Guardrail.Connector = "codex"
			cfg.Codex.Mode = tc.hookMode
			cfg.Guardrail.Profiles = profiles
			set, err := newGuardrailProfileSet(cfg, nil, true)
			if err != nil {
				t.Fatal(err)
			}
			name, single := set.meetOf([]string{"a", "b"}, "codex")
			if single || !config.IsProfileMeet(name) {
				t.Fatalf("selection = %q, single %v; want a meet", name, single)
			}
			derived, ok := set.derivedProfile(name)
			if !ok {
				t.Fatal("meet did not derive")
			}
			if got := derived.Config.HookModeForConnector("codex"); got != tc.hookMode {
				t.Errorf("Codex hook mode = %q, want %q", got, tc.hookMode)
			}
			if got := inspectMode(derived.Config, "codex"); got != tc.guardrailMode {
				t.Errorf("Codex inspect mode = %q, want %q", got, tc.guardrailMode)
			}
			verdict := &ToolInspectVerdict{Action: "block", Severity: "HIGH"}
			verdict.applyMode(inspectMode(derived.Config, "codex"))
			if verdict.Action != tc.wantAction || verdict.WouldBlock != tc.wantWouldBlock {
				t.Errorf("inspect finding under the meet = %+v; want action %s, would block %v", verdict, tc.wantAction, tc.wantWouldBlock)
			}
		})
	}
}

// meetTestSet is a profile set of profiles, with no assignments.
func meetTestSet(t *testing.T, profiles map[string]config.GuardrailProfile) *guardrailProfileSet {
	t.Helper()
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Profiles = profiles
	set, err := newGuardrailProfileSet(cfg, nil, true)
	if err != nil || set == nil {
		t.Fatalf("profile set: %v", err)
	}
	return set
}

// The meet of profiles, field by field: every block of any member applies
// (the action mode wherever one blocks, the lowest block level of those
// that block), the strictest HILT of those that block, per connector.
func TestProfileMeetTable(t *testing.T) {
	hilt := func(enabled bool, severity string) *config.HILTConfig {
		return &config.HILTConfig{Enabled: enabled, MinSeverity: severity}
	}
	for _, tc := range []struct {
		name      string
		profiles  map[string]config.GuardrailProfile
		connector string
		mode      string
		blockAt   string
		hilt      bool
		hiltAt    int
	}{
		{name: "an observing member adds no block", connector: "codex",
			profiles: map[string]config.GuardrailProfile{"a": {Mode: "action", BlockAt: "HIGH"}, "b": {Mode: "observe", BlockAt: "LOW"}},
			mode:     "action", blockAt: "HIGH"},
		{name: "the lowest block level of the members that block", connector: "codex",
			profiles: map[string]config.GuardrailProfile{"a": {Mode: "action", BlockAt: "HIGH"}, "b": {Mode: "action", BlockAt: "LOW"}},
			mode:     "action", blockAt: "LOW"},
		{name: "members that only observe", connector: "codex",
			profiles: map[string]config.GuardrailProfile{"a": {Mode: "observe", BlockAt: "LOW"}, "b": {Mode: "observe", BlockAt: "HIGH"}},
			mode:     "observe", blockAt: "CRITICAL"},
		{name: "a HILT of one member", connector: "codex",
			profiles: map[string]config.GuardrailProfile{"a": {Mode: "action", BlockAt: "CRITICAL", HILT: hilt(true, "HIGH")}, "b": {Mode: "action", BlockAt: "HIGH"}},
			mode:     "action", blockAt: "HIGH", hilt: true, hiltAt: severityHigh},
		{name: "the HILT that asks most", connector: "codex",
			profiles: map[string]config.GuardrailProfile{"a": {Mode: "action", BlockAt: "CRITICAL", HILT: hilt(true, "HIGH")}, "b": {Mode: "action", BlockAt: "CRITICAL", HILT: hilt(true, "MEDIUM")}},
			mode:     "action", blockAt: "CRITICAL", hilt: true, hiltAt: severityMedium},
		{name: "a connector one member blocks", connector: "codex",
			profiles: map[string]config.GuardrailProfile{
				"a": {Mode: "observe", Connectors: map[string]config.PerConnectorGuardrailConfig{"codex": {Mode: "action", BlockAt: "MEDIUM"}}},
				"b": {Mode: "observe"}},
			mode: "action", blockAt: "MEDIUM"},
		{name: "another connector of that member observes", connector: "claudecode",
			profiles: map[string]config.GuardrailProfile{
				"a": {Mode: "observe", Connectors: map[string]config.PerConnectorGuardrailConfig{"codex": {Mode: "action", BlockAt: "MEDIUM"}}},
				"b": {Mode: "observe"}},
			mode: "observe", blockAt: "CRITICAL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set := meetTestSet(t, tc.profiles)
			name, single := set.meetOf([]string{"b", "a"}, tc.connector)
			if single {
				// One covers the other: it applies under its own name, and
				// enforces what the meet would.
				t.Logf("%s covers the other", name)
			}
			if !single && name != config.ProfileMeetName([]string{"a", "b"}) {
				t.Fatalf("meet named %q", name)
			}
			cfg := set.profileConfig(name)
			if got := cfg.HookModeForConnector(tc.connector); got != tc.mode {
				t.Errorf("hook mode %q, want %q", got, tc.mode)
			}
			if got := inspectMode(cfg, tc.connector); got != tc.mode {
				t.Errorf("inspect mode %q, want %q", got, tc.mode)
			}
			if tc.mode == "action" {
				if got := resolveThresholds(cfg, tc.connector).Block; got != tc.blockAt {
					t.Errorf("block_at %q, want %q", got, tc.blockAt)
				}
				if got := hiltEnabledForConfig(cfg, tc.connector); got != tc.hilt {
					t.Errorf("HILT %v, want %v", got, tc.hilt)
				}
				if tc.hilt && hiltMinRankForConfig(cfg, tc.connector) != tc.hiltAt {
					t.Errorf("HILT at %d, want %d", hiltMinRankForConfig(cfg, tc.connector), tc.hiltAt)
				}
			}
			// The meet is never weaker than a member that blocks.
			for _, member := range []string{"a", "b"} {
				m := set.profileConfig(member)
				if m.HookModeForConnector(tc.connector) == "action" {
					mb, _ := guardrailThresholdRanks(resolveThresholds(m, tc.connector))
					cb, _ := guardrailThresholdRanks(resolveThresholds(cfg, tc.connector))
					if cfg.HookModeForConnector(tc.connector) != "action" || cb > mb {
						t.Errorf("the meet blocks less than %s", member)
					}
				}
			}
		})
	}
}

// Profiles that enforce different rule packs or sandbox sections: their
// meet applies, never a refusal, and it keeps the sandbox limits of both.
func TestProfileMeetOfDifferentSandboxSections(t *testing.T) {
	set := meetTestSet(t, map[string]config.GuardrailProfile{
		"a": {Mode: "action", BlockAt: "HIGH", Sandbox: &config.OpenShellAdminConfig{RequiredFor: []string{"codex"}, EgressBlock: []string{"a.example"}}},
		"b": {Mode: "action", BlockAt: "LOW", Sandbox: &config.OpenShellAdminConfig{EgressBlock: []string{"b.example"}, AllowedHarnesses: []string{"codex", "claudecode"}}},
	})
	name, single := set.meetOf([]string{"a", "b"}, "codex")
	if single || !config.IsProfileMeet(name) {
		t.Fatalf("%q single %v; want the meet", name, single)
	}
	derived, ok := set.derivedProfile(name)
	if !ok {
		t.Fatal("the meet did not derive")
	}
	f := derived.Sandbox
	if !slices.Contains(f.RequiredFor, "codex") || !slices.Contains(f.EgressBlock, "a.example") || !slices.Contains(f.EgressBlock, "b.example") ||
		len(f.AllowedHarnesses) != 2 || resolveThresholds(derived.Config, "codex").Block != "LOW" {
		t.Fatalf("meet floor %+v, block %s; want both members' limits", f, resolveThresholds(derived.Config, "codex").Block)
	}
	// The same meet resolves after a restart from its name alone.
	if again, ok := newGuardrailProfileSetFor(t, set.base).derivedProfile(name); !ok || again.Digest != derived.Digest {
		t.Fatalf("meet %q does not resolve by name in another set", name)
	}
}

func newGuardrailProfileSetFor(t *testing.T, cfg *config.Config) *guardrailProfileSet {
	t.Helper()
	set, err := newGuardrailProfileSet(cfg, nil, true)
	if err != nil || set == nil {
		t.Fatalf("profile set: %v", err)
	}
	return set
}

// A rule any member's pack enforces is enforced: the meet's generation has
// every rule of every member, one the members define the same way once.
func TestProfileMeetEnforcesTheRulesOfEveryPack(t *testing.T) {
	rule := func(id, pattern, severity string) PatternRule {
		return PatternRule{ID: id, Pattern: regexp.MustCompile(pattern), Title: id, Severity: severity, Confidence: 0.9}
	}
	a, err := compileRulePackGeneration([]ruleCategory{{Name: "cmd", Rules: []PatternRule{rule("R-SHARED", "rm -rf", "HIGH"), rule("R-A", "curl evil", "HIGH")}}})
	if err != nil {
		t.Fatal(err)
	}
	b, err := compileRulePackGeneration([]ruleCategory{
		{Name: "cmd", Rules: []PatternRule{rule("R-SHARED", "rm -rf", "HIGH")}},
		{Name: "secrets", Rules: []PatternRule{rule("R-B", "AKIA[0-9A-Z]{16}", "CRITICAL")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	merged, err := mergeRuleGenerations([]*compiledRulePackCategories{a, b})
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]int{}
	for _, category := range merged.categories {
		for _, r := range category.Rules {
			ids[r.ID]++
		}
	}
	if ids["R-SHARED"] != 1 || ids["R-A"] != 1 || ids["R-B"] != 1 {
		t.Fatalf("merged rules %v; want each rule once", ids)
	}
	for _, text := range []string{"rm -rf /", "curl evil.sh", "AKIAABCDEFGHIJKLMNOP"} {
		if findings := scanRuleGeneration(merged, text, "Bash", ruleScanOptions{}); len(findings) == 0 {
			t.Errorf("%q: no finding; want the member's rule to fire", text)
		}
	}
}

// Allows are the intersection: a suppression applies only when every
// member's pack has it; a sensitive tool any member inspects is inspected.
func TestProfileMeetIntersectsSuppressionsAndUnionsSensitiveTools(t *testing.T) {
	shared := guardrail.FindingSuppression{ID: "shared", FindingPattern: "PII-EMAIL"}
	only := guardrail.FindingSuppression{ID: "only-a", FindingPattern: "SECRET-KEY"}
	a := &guardrail.RulePack{Suppressions: &guardrail.SuppressionsConfig{FindingSupps: []guardrail.FindingSuppression{shared, only}},
		SensitiveTools: &guardrail.SensitiveToolsConfig{Tools: []guardrail.SensitiveTool{{Name: "read_db", MinEntitiesAlert: 5}}}}
	b := &guardrail.RulePack{Suppressions: &guardrail.SuppressionsConfig{FindingSupps: []guardrail.FindingSuppression{shared}},
		SensitiveTools: &guardrail.SensitiveToolsConfig{Tools: []guardrail.SensitiveTool{{Name: "read_db", ResultInspection: true, MinEntitiesAlert: 2}, {Name: "fetch", JudgeResult: true}}}}
	merged := mergeRulePacks([]*guardrail.RulePack{a, b}, false)
	if len(merged.Suppressions.FindingSupps) != 1 || merged.Suppressions.FindingSupps[0].ID != "shared" {
		t.Fatalf("suppressions %+v; want only the shared one", merged.Suppressions.FindingSupps)
	}
	db := merged.LookupSensitiveTool("read_db")
	if db == nil || !db.ResultInspection || db.MinEntitiesAlert != 2 || merged.LookupSensitiveTool("fetch") == nil {
		t.Fatalf("sensitive tools %+v; want every tool at its strictest", merged.SensitiveTools)
	}
	if none := mergeRulePacks([]*guardrail.RulePack{a, b}, true); len(none.Suppressions.FindingSupps) != 0 {
		t.Fatalf("a member with no pack: suppressions %+v; want none", none.Suppressions.FindingSupps)
	}
	if len(a.Suppressions.FindingSupps) != 2 {
		t.Fatal("the merge changed a member's pack")
	}
}

// Overlapping proven assignments whose profiles enforce different rules:
// their meet applies whatever the order, never one that drops the other's
// sandbox denial or block level.
func TestOverlappingProvenAssignmentsApplyTheirMeet(t *testing.T) {
	p := identityTestPlatforms[0]
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"sandboxed": {Mode: "action", BlockAt: "HIGH", Sandbox: &config.OpenShellAdminConfig{RequiredFor: []string{"codex"}}},
		"low":       {Mode: "action", BlockAt: "LOW"},
	}
	byUser := config.ProfileAssignment{Profile: "sandboxed", Match: config.ProfileMatch{Users: []string{p.id}}}
	byGroup := config.ProfileAssignment{Profile: "low", Match: config.ProfileMatch{Groups: []string{p.group}}}
	subject := identityTestSubject(p, p.providers[1], stateProven, true)
	want := config.ProfileMeetName([]string{"low", "sandboxed"})
	for _, order := range [][]config.ProfileAssignment{{byUser, byGroup}, {byGroup, byUser}} {
		cfg.Guardrail.ProfileAssignments = order
		set := newGuardrailProfileSetFor(t, cfg)
		got := set.match(&subject, profileSubjectVerified, "codex", "")
		if got.Name != want || got.Assignment != 1 || len(got.Candidates) != 2 {
			t.Fatalf("order %+v: %+v; want %s reported as the first assignment", order, got, want)
		}
		derived, _ := set.derivedProfile(got.Name)
		if resolveThresholds(derived.Config, "codex").Block != "LOW" || !slices.Contains(derived.Sandbox.RequiredFor, "codex") {
			t.Fatalf("meet %+v; want block_at LOW and codex required in a sandbox", derived)
		}
	}
}

// Windows: 1.0.0 to 1.0.3 keyed an agent identity of a SID on the SID, as
// 1.0.4 does, so an agents entry written for it keeps matching exactly
// after the upgrade, with no migration map.
func TestUpgradeKeepsWindowsAgentsAssignments(t *testing.T) {
	in := agentidentity.Inputs{MachineHash: "m", UserID: "S-1-5-21-9-9-9-1105", Connector: "codex", InstallFP: `C:\Users\alice\.codex`, Account: `CORP\alice`}
	if agentidentity.LegacyAgentID(in) != "" {
		t.Fatal("a SID's 1.0.3 identity differs from its current one")
	}
	agent := agentidentity.AgentID(in)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{"relaxed": {Mode: "observe"}, "strict": {Mode: "action", BlockAt: "LOW"}}
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{{Profile: "relaxed", Match: config.ProfileMatch{Agents: []string{agent}}}}
	cfg.Guardrail.DefaultProfile = "strict"
	set := newGuardrailProfileSetFor(t, cfg)
	subject := profileSubjectFromVerified(VerifiedSubject{UserID: in.UserID, IDKind: useridentity.KindWindowsSID, UserName: `CORP\alice`,
		Directory: useridentity.DirectoryFacts{Source: useridentity.SourceWindowsLSA, Directory: useridentity.DirectoryActiveDirectory,
			Assurance: useridentity.AssuranceVerified}}, true)
	got := set.matchAgent(&subject, profileSubjectVerified, "codex", agent, func() (profileAgentClaim, bool) { return profileAgentClaim{}, true })
	if got.Name != "relaxed" || got.Match != profileMatchAgent {
		t.Fatalf("Windows 1.0.x agents entry: %+v; want relaxed by agent", got)
	}
}

// GAP-0487: a Windows group name whose SID lookup is in flight or failed may
// name one of the token's groups: its assignment is a candidate, never a
// definite no that lets a weaker default apply. A name the directory says
// is no group is a no.
func TestPendingWindowsGroupNameIsACandidate(t *testing.T) {
	p := identityTestPlatforms[2]
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{name: "lookup in flight", want: "strict"},
		{name: "lookup failed", err: errProfileGroupLookupsFull, want: "strict"},
		{name: "no such group", err: errProfileGroupUnknown, want: "watch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set := identityTestSet(t, p, "watch", config.ProfileAssignment{Profile: "strict", Match: config.ProfileMatch{Groups: []string{`CORP\Engineers`}}})
			set.groupSIDs = &profileGroupSIDs{entries: map[string]*profileGroupSIDEntry{
				foldKey(`CORP\Engineers`): {name: `CORP\Engineers`, err: tc.err},
			}}
			subject := identityTestSubject(p, p.providers[0], stateProven, false)
			got := set.matchUncached(&subject, profileSubjectVerified, "codex", "")
			if got.Name != tc.want {
				t.Fatalf("%+v; want %s", got, tc.want)
			}
			if tc.err != errProfileGroupUnknown &&
				(got.Refused == "" || !strings.Contains(got.Refused, "assignment group SID is unconfirmed")) {
				t.Fatalf("pending SID lookup did not refuse with its missing fact: %+v", got)
			}
			if tc.err == errProfileGroupUnknown && got.Refused != "" {
				t.Fatalf("proven absent group refused: %+v", got)
			}
		})
	}
}
