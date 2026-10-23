// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// meetMarkerGeneration is semanticRules semantic rules named prefix plus one
// content rule matching prefix's plain marker (meetPlainMarker).
func meetMarkerGeneration(t *testing.T, prefix string, semanticRules int) *compiledRulePackCategories {
	t.Helper()
	categories := []ruleCategory{{Name: "secret", Rules: []PatternRule{{
		ID: prefix + "-PLAIN", Title: prefix + " plain marker",
		Pattern:  regexp.MustCompile(regexp.QuoteMeta(meetPlainMarker(prefix))),
		Severity: "HIGH", Confidence: 0.99,
	}}}}
	if semanticRules > 0 {
		categories = append(categories, meetSemanticGeneration(t, prefix, semanticRules).categories...)
	}
	compiled, err := compileRulePackGeneration(categories)
	if err != nil {
		t.Fatalf("compile %s: %v", prefix, err)
	}
	return compiled
}

func meetPlainMarker(prefix string) string {
	return strings.ToLower(strings.ReplaceAll(prefix, "-", "_")) + "_plain_marker"
}

// generationRuleIDs lists the rule IDs of g.
func generationRuleIDs(g *compiledRulePackCategories) []string {
	var ids []string
	if g == nil {
		return nil
	}
	for _, category := range g.categories {
		for _, rule := range category.Rules {
			ids = append(ids, rule.ID)
		}
	}
	return ids
}

// A gateway connector configured under an alias (claude-code, claude_code,
// any case) is one scope under one name. The profile decision checks the
// merge of the very generation the scan reads, so a merge that compiles for
// the checked spelling can never be swapped at scan time for one that does
// not, which would fall back to the global rules and drop a member's
// blocking rule. Here the members' Claude Code merge compiles, while a
// merge with the global rules would exceed the semantic rule limit.
func TestConnectorAliasScansTheGenerationItsMeetChecked(t *testing.T) {
	stubProfileSources(t)
	for _, alias := range []string{"claude-code", "claude_code", "Claude-Code", "CLAUDECODE"} {
		for _, failing := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/claudecode merge fails %v", alias, failing), func(t *testing.T) {
				if got := canonicalConnectorRulePackKey(alias); got != "claudecode" {
					t.Errorf("rule scope of %q = %q, want claudecode", alias, got)
				}
				root := t.TempDir()
				cfg := &config.Config{}
				cfg.Guardrail.Mode = "action"
				cfg.Guardrail.Connector = alias
				cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
					"a": {Mode: "action", BlockAt: "HIGH", Connectors: map[string]config.PerConnectorGuardrailConfig{
						"claudecode": {RulePackDir: meetRulePackDir(t, root, "ALIAS-A")}}},
					"b": {Mode: "action", BlockAt: "MEDIUM"},
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
				set.rules[effectiveRulePackKey(set.profiles["a"].Config, "claudecode")] = meetMarkerGeneration(t, "ALIAS-A", 2)
				baseClaude := meetMarkerGeneration(t, "BASE-CLAUDE", 1)
				if failing {
					baseClaude = meetMarkerGeneration(t, "BASE-CLAUDE", maxGenerationSemanticRules-1)
				}
				// b scans with the base generation: its Claude Code rules,
				// and global rules that cannot merge with a's.
				g := &Generation{N: 1, Profiles: set,
					activeRules:     meetMarkerGeneration(t, "BASE-GLOBAL", maxGenerationSemanticRules-1),
					connectorRules:  map[string]*compiledRulePackCategories{"claudecode": baseClaude},
					registeredRules: map[string]*compiledRulePackCategories{},
				}
				api := &APIServer{scannerCfg: cfg}
				api.guardrailProfiles.set.Store(set)
				ctx := context.WithValue(t.Context(), testVerifiedSubjectKey{}, identityTestSubject(p, p.providers[0], stateProven, true))
				ctx = withPinnedGeneration(ctx, g)
				meetName := config.ProfileMeetName([]string{"a", "b"})

				// The scope every request kind scans is one its decision checked.
				for _, rq := range []profileScopeRequest{
					{name: "aliased hook", hook: alias},
					{name: "aliased inspect credential", inspect: alias, path: "/api/v1/inspect/tool"},
					{name: "unscoped tool inspect", path: "/api/v1/inspect/tool"},
					{name: "unscoped decision without a route"},
				} {
					decision, scan := resolveProfileScope(t, api, ctx, rq)
					if decision.Name != meetName || (decision.Refused != "") != failing {
						t.Errorf("%s: decision %+v; want the meet, refused %v", rq.name, decision, failing)
					}
					if rq.path != "" || rq.hook != "" {
						if scan != "claudecode" {
							t.Errorf("%s scans %q, want claudecode", rq.name, scan)
						}
					}
				}

				body := fmt.Sprintf(`{"tool":"message","content":"%s"}`, meetPlainMarker("ALIAS-A"))
				req := httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool", strings.NewReader(body)).WithContext(ctx)
				rec := httptest.NewRecorder()
				api.guardrailProfileInspectMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if !failing {
						ids := generationRuleIDs(snapshotRulePackGenerationFor(r.Context(), canonicalConnectorRulePackKey(api.connectorName())))
						if !slices.Contains(ids, "ALIAS-A-PLAIN") || !slices.Contains(ids, "BASE-CLAUDE-PLAIN") || slices.Contains(ids, "BASE-GLOBAL-PLAIN") {
							t.Errorf("unscoped tool inspect scans rules %v; want the Claude Code meet of a and the base Claude Code rules", ids)
						}
					}
					api.handleInspectTool(w, r)
				})).ServeHTTP(rec, req)
				if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"action":"block"`) {
					t.Fatalf("a's blocking rule did not block the unscoped tool inspect: %d %s", rec.Code, rec.Body.String())
				}
				if failing != strings.Contains(rec.Body.String(), "rule packs") {
					t.Fatalf("unscoped tool inspect: refusal %v, want %v: %s", !failing, failing, rec.Body.String())
				}
			})
		}
	}
}

// A request compares profiles on the scopes it scans, and a meet adds only
// the rules of members that block on the scanned connector. a blocks on
// Codex and observes elsewhere; b observes on Codex and blocks elsewhere.
// Neither turns the other's observation into a block: a Codex request
// gets a, a Claude Code or global request gets b, and the meet an unscoped
// decision takes (it may scan either scope) scans Codex with a's rules
// only and the global scope with b's only.
func TestObserveOnlyProfileAddsNoBlockingRulesToItsConnector(t *testing.T) {
	stubProfileSources(t)
	for _, order := range [][2]string{{"a", "b"}, {"b", "a"}} {
		t.Run("user "+order[0]+", group "+order[1], func(t *testing.T) {
			root := t.TempDir()
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "observe"
			cfg.Guardrail.Connector = "codex"
			cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
				"a": {Mode: "observe", RulePackDir: meetRulePackDir(t, root, "OBS-A-GLOBAL"),
					Connectors: map[string]config.PerConnectorGuardrailConfig{
						"codex": {Mode: "action", RulePackDir: meetRulePackDir(t, root, "OBS-A-CODEX")}}},
				"b": {Mode: "action", RulePackDir: meetRulePackDir(t, root, "OBS-B"),
					Connectors: map[string]config.PerConnectorGuardrailConfig{"codex": {Mode: "observe"}}},
				"c": {Mode: "observe", Connectors: map[string]config.PerConnectorGuardrailConfig{
					"codex": {Mode: "action", RulePackDir: meetRulePackDir(t, root, "OBS-C-CODEX")}}},
			}
			p := identityTestPlatforms[0]
			cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
				{Profile: order[0], Match: config.ProfileMatch{Users: []string{p.id}}},
				{Profile: order[1], Match: config.ProfileMatch{Groups: []string{p.group}}},
			}
			set, err := newGuardrailProfileSet(cfg, nil, true)
			if err != nil {
				t.Fatal(err)
			}
			for _, scope := range []struct{ profile, connector, prefix string }{
				{"a", "", "OBS-A-GLOBAL"}, {"a", "codex", "OBS-A-CODEX"},
				{"b", "", "OBS-B"}, {"b", "codex", "OBS-B"}, {"c", "codex", "OBS-C-CODEX"},
			} {
				set.rules[effectiveRulePackKey(set.profiles[scope.profile].Config, scope.connector)] = meetMarkerGeneration(t, scope.prefix, 0)
			}
			for _, fixture := range []struct {
				profile, connector string
				blocks             bool
			}{
				{"a", "codex", true}, {"a", "claudecode", false}, {"a", "", false},
				{"b", "codex", false}, {"b", "claudecode", true}, {"b", "", true},
			} {
				m := set.profileConfig(fixture.profile)
				if got := inspectMode(m, fixture.connector) == "action"; got != fixture.blocks {
					t.Fatalf("fixture: %s inspect blocks on %q = %v", fixture.profile, fixture.connector, got)
				}
				if fixture.connector != "" {
					if got := hookModeForConfig(m, fixture.connector) == "action"; got != fixture.blocks {
						t.Fatalf("fixture: %s hook blocks on %q = %v", fixture.profile, fixture.connector, got)
					}
				}
			}
			api := &APIServer{scannerCfg: cfg}
			api.guardrailProfiles.set.Store(set)
			ctx := context.WithValue(t.Context(), testVerifiedSubjectKey{}, identityTestSubject(p, p.providers[0], stateProven, true))
			meetName := config.ProfileMeetName([]string{"a", "b"})
			want := map[string]string{
				"Codex hook":                        "a",
				"Claude Code hook":                  "b",
				"unscoped tool inspect":             "a",
				"unscoped prompt inspect":           "b",
				"Codex-scoped tool inspect":         "a",
				"Claude Code-scoped tool inspect":   "b",
				"unscoped decision without a route": meetName,
			}
			for _, rq := range profileScopeRequests {
				decision, _ := resolveProfileScope(t, api, ctx, rq)
				if decision.Name != want[rq.name] || decision.Refused != "" {
					t.Errorf("%s: decision %+v; want %q", rq.name, decision, want[rq.name])
				}
			}
			for _, tc := range []struct {
				members         []string
				connector       string
				want, forbidden []string
			}{
				{[]string{"a", "b"}, "codex", []string{"OBS-A-CODEX-PLAIN"}, []string{"OBS-B-PLAIN"}},
				{[]string{"a", "b"}, "", []string{"OBS-B-PLAIN"}, []string{"OBS-A-GLOBAL-PLAIN"}},
				{[]string{"a", "b", "c"}, "codex", []string{"OBS-A-CODEX-PLAIN", "OBS-C-CODEX-PLAIN"}, []string{"OBS-B-PLAIN"}},
				{[]string{"a", "b", "c"}, "claudecode", []string{"OBS-B-PLAIN"}, []string{"OBS-A-GLOBAL-PLAIN"}},
			} {
				meet := set.meet(config.ProfileMeetName(tc.members))
				if meet == nil {
					t.Fatalf("meet of %v did not derive", tc.members)
				}
				generation, err := meet.ruleGeneration(ctx, set, tc.connector)
				if err != nil {
					t.Fatalf("meet of %v on %q: %v", tc.members, tc.connector, err)
				}
				ids := generationRuleIDs(generation)
				for _, id := range tc.want {
					if !slices.Contains(ids, id) {
						t.Errorf("meet of %v on %q scans %v; want %s", tc.members, tc.connector, ids, id)
					}
				}
				for _, id := range tc.forbidden {
					if slices.Contains(ids, id) {
						t.Errorf("meet of %v on %q scans %v; %s only observes there", tc.members, tc.connector, ids, id)
					}
				}
			}
			// The B-only match on a Codex request is observed, as b observes
			// there, never blocked.
			hook := api.withGuardrailProfileDecision(withAuthenticatedHookConnector(ctx, "codex"), "codex")
			if findings := scanAllRulesForConnectorFor(hook, "codex", meetPlainMarker("OBS-B"), "message"); len(findings) != 0 {
				t.Errorf("Codex hook scan found b's observe-only rule: %+v", findings)
			}
			if findings := scanAllRulesForConnectorFor(hook, "codex", meetPlainMarker("OBS-A-CODEX"), "message"); len(findings) == 0 {
				t.Error("Codex hook scan missed a's blocking rule")
			}
		})
	}
}
