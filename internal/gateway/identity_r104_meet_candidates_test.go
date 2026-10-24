// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// One rule, per connector: the profile a request gets enforces, on every
// scope the request scans, everything each candidate profile enforces
// there in its own mode, or the request is refused. The proven profiles of
// a and c may stand for an uncertain candidate b only when they scan every
// rule b blocks with there, block on every path b blocks on, from b's
// level or lower, and ask wherever b asks. A candidate that only observes
// on the scanned scopes adds nothing: the request gets what it gets
// without b's assignment, never a refusal. Every built-in connector and
// its aliases (claude-code, claude_code, any case) are one canonical
// scope, however the gateway, a hook route, an inspect credential, an
// assignment or a profile's connectors key spells it. The checks read the
// rules and settings each side scans, not the coverage code.
func TestEveryCandidateProfileIsEnforcedInItsOwnModePerConnector(t *testing.T) {
	stubProfileSources(t)
	root := t.TempDir()
	packA, packB, packC := meetRulePackDir(t, root, "PA"), meetRulePackDir(t, root, "PB"), meetRulePackDir(t, root, "PC")
	acts := func(dir string) config.GuardrailProfile {
		return config.GuardrailProfile{Mode: "action", BlockAt: "HIGH", RulePackDir: dir}
	}
	actsOn := func(spelling, dir string) config.GuardrailProfile {
		return config.GuardrailProfile{Mode: "observe", BlockAt: "HIGH", Connectors: map[string]config.PerConnectorGuardrailConfig{
			spelling: {Mode: "action", BlockAt: "HIGH", RulePackDir: dir}}}
	}
	spellings := append(connector.NewDefaultRegistry().Names(), "claude-code", "claude_code", "Claude-Code", "CODEX")
	for _, spelling := range spellings {
		scope := config.NormalizeConnectorName(spelling)
		// Codex and the claude-code alias get the whole table (Codex in
		// both assignment orders); every other spelling gets the sharpest
		// cases, assigned under its own name.
		full := spelling == "codex" || spelling == "claude-code"
		sharp := []string{"base pack", "acts on the connector only, own pack", "observes"}
		members := []struct {
			name       string
			a, c       config.GuardrailProfile
			everywhere bool
		}{
			{"members act everywhere", acts(packA), acts(packC), true},
			{"members act on the connector only", actsOn(spelling, packA), actsOn(spelling, packC), false},
			{"first member observes", config.GuardrailProfile{Mode: "observe", RulePackDir: packA}, acts(packC), false},
		}
		candidates := []struct {
			name string
			b    config.GuardrailProfile
			// covered: b adds nothing on any request; coveredByMembersEverywhere:
			// it adds nothing when a and c act everywhere.
			covered, coveredByMembersEverywhere bool
		}{
			{name: "base pack", b: acts("")},
			{name: "first member's pack", b: acts(packA), coveredByMembersEverywhere: true},
			{name: "later member's pack", b: acts(packC)},
			{name: "own pack", b: acts(packB)},
			{name: "observes", b: config.GuardrailProfile{Mode: "observe"}, covered: true},
			{name: "observes with its own pack", b: config.GuardrailProfile{Mode: "observe", RulePackDir: packB}, covered: true},
			{name: "acts on the connector only, own pack", b: actsOn(spelling, packB)},
			{name: "acts on the connector only, base pack", b: actsOn(spelling, "")},
			{name: "observes on the connector only", b: config.GuardrailProfile{Mode: "action", BlockAt: "HIGH", RulePackDir: packB,
				Connectors: map[string]config.PerConnectorGuardrailConfig{spelling: {Mode: "observe"}}}},
			{name: "first member's pack, lower block level", b: config.GuardrailProfile{Mode: "action", BlockAt: "MEDIUM", RulePackDir: packA}},
			{name: "first member's pack, HILT", b: config.GuardrailProfile{Mode: "action", BlockAt: "HIGH", RulePackDir: packA,
				HILT: &config.HILTConfig{Enabled: true, MinSeverity: "MEDIUM"}}},
		}
		requests := []struct {
			rq     profileScopeRequest
			scopes []string
		}{
			{profileScopeRequest{name: "hook", hook: spelling}, []string{scope}},
			{profileScopeRequest{name: "inspect credential", inspect: spelling, path: "/api/v1/inspect/tool"}, []string{scope}},
			{profileScopeRequest{name: "unscoped tool inspect", path: "/api/v1/inspect/tool"}, []string{scope}},
			{profileScopeRequest{name: "unscoped prompt inspect", path: "/api/v1/inspect/request"}, []string{""}},
			{profileScopeRequest{name: "unscoped decision without a route"}, []string{"", scope}},
		}
		for i, m := range members {
			for _, tc := range candidates {
				for _, scoped := range []bool{false, true} {
					if !full && (i != 1 || !scoped || !slices.Contains(sharp, tc.name)) {
						continue
					}
					p := identityTestPlatforms[0]
					byName := config.ProfileAssignment{Profile: "b", Match: config.ProfileMatch{Users: []string{`.\` + p.name}}}
					byGroup := config.ProfileAssignment{Profile: "a", Match: config.ProfileMatch{Groups: []string{p.group}}}
					byUID := config.ProfileAssignment{Profile: "c", Match: config.ProfileMatch{Users: []string{p.id}}}
					style := "assigned everywhere"
					if scoped {
						// b's assignment names the connector as configured.
						style = "assigned to " + spelling
						byName.Match.Connectors = []string{spelling}
					}
					orders := [][]config.ProfileAssignment{{byName, byGroup, byUID}, {byGroup, byUID, byName}}
					if spelling != "codex" {
						orders = orders[:1]
					}
					for _, order := range orders {
						t.Run(spelling+"/"+m.name+"/"+tc.name+"/"+style+"/"+order[0].Profile+" first", func(t *testing.T) {
							t.Parallel()
							profileSetOf := func(assignments []config.ProfileAssignment) (*APIServer, context.Context, *guardrailProfileSet) {
								cfg := &config.Config{}
								cfg.Guardrail.Mode = "observe"
								cfg.Guardrail.Connector = spelling
								cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{"a": m.a, "b": tc.b, "c": m.c}
								cfg.Guardrail.ProfileAssignments = assignments
								set := newGuardrailProfileSetFor(t, cfg)
								g := &Generation{N: 1, Profiles: set,
									activeRules:     meetMarkerGeneration(t, "BASE-GLOBAL", 0),
									connectorRules:  map[string]*compiledRulePackCategories{scope: meetMarkerGeneration(t, "BASE-CONN", 0)},
									registeredRules: map[string]*compiledRulePackCategories{},
								}
								api := &APIServer{scannerCfg: cfg}
								api.guardrailProfiles.set.Store(set)
								// A local account on a per-user SSSD host: its uid
								// and groups are proven, which account holds the
								// uid is not.
								subject := identityTestSubject(p, p.providers[0], stateProven, true)
								subject.holderUnproven = true
								return api, withPinnedGeneration(context.WithValue(t.Context(), testVerifiedSubjectKey{}, subject), g), set
							}
							api, ctx, set := profileSetOf(order)
							var withoutB *APIServer
							var withoutBCtx context.Context
							rulesOf := func(name, on string) []string {
								if meet := set.meet(name); meet != nil {
									return generationRuleIDs(meet.ruleGeneration(ctx, set, on))
								}
								return generationRuleIDs(set.memberRuleGeneration(ctx, name, on))
							}
							cb := set.profileConfig("b")
							for _, r := range requests {
								decision, _ := resolveProfileScope(t, api, ctx, r.rq)
								// A connector assignment is a candidate only for a
								// request that recorded that connector.
								candidate := !scoped || r.rq.hook != "" || r.rq.inspect != ""
								blocks := false
								for _, on := range r.scopes {
									hookB, inspectB := hookModeForConfig(cb, on) == "action", inspectMode(cb, on) == "action"
									if !candidate || !hookB && !inspectB {
										continue
									}
									blocks = true
									if decision.Refused != "" {
										continue
									}
									// Not refused: the decision enforces b there.
									cd := set.profileConfig(decision.Name)
									if hookB && hookModeForConfig(cd, on) != "action" || inspectB && inspectMode(cd, on) != "action" {
										t.Errorf("%s: %s observes on %q where b blocks", r.rq.name, decision.Name, on)
									}
									have := rulesOf(decision.Name, on)
									for _, id := range rulesOf("b", on) {
										if !slices.Contains(have, id) {
											t.Errorf("%s: %s scans %q with %v, without b's blocking rule %s", r.rq.name, decision.Name, on, have, id)
										}
									}
									blockD, _ := guardrailThresholdRanks(resolveThresholds(cd, on))
									blockB, _ := guardrailThresholdRanks(resolveThresholds(cb, on))
									if blockD > blockB {
										t.Errorf("%s: %s blocks on %q from a higher level than b", r.rq.name, decision.Name, on)
									}
									if !hiltCovers(hiltEnabledForConfig(cd, on), hiltMinRankForConfig(cd, on), hiltEnabledForConfig(cb, on), hiltMinRankForConfig(cb, on)) {
										t.Errorf("%s: %s does not ask on %q where b asks", r.rq.name, decision.Name, on)
									}
								}
								switch {
								case !blocks || tc.covered || tc.coveredByMembersEverywhere && m.everywhere:
									// b adds nothing: the decision without b, never a refusal.
									if withoutB == nil {
										withoutB, withoutBCtx, _ = profileSetOf(slices.DeleteFunc(slices.Clone(order),
											func(a config.ProfileAssignment) bool { return a.Profile == "b" }))
									}
									control, _ := resolveProfileScope(t, withoutB, withoutBCtx, r.rq)
									if decision.Refused != "" || decision.Name != control.Name || control.Refused != "" {
										t.Errorf("%s: decision %+v; want %q, as without b's assignment, not refused", r.rq.name, decision, control.Name)
									}
								case decision.Refused != "":
									if !slices.Contains(decision.Unproven, "account:unknown") {
										t.Errorf("%s: refusal %+v does not name the missing account fact", r.rq.name, decision)
									}
								}
								if r.rq.hook == "" || decision.Refused != "" || !blocks {
									continue
								}
								// The hook scan finds every fixture rule b blocks with.
								hook := api.withGuardrailProfileDecision(withAuthenticatedHookConnector(ctx, spelling), spelling)
								var want, text []string
								for _, id := range rulesOf("b", scope) {
									if prefix, ok := strings.CutSuffix(id, "-FIXTURE"); ok {
										want, text = append(want, id), append(text, prefix+"_fixture_marker")
									} else if prefix, ok := strings.CutSuffix(id, "-PLAIN"); ok {
										want, text = append(want, id), append(text, meetPlainMarker(prefix))
									}
								}
								var found []string
								for _, finding := range scanAllRulesForConnectorFor(hook, scope, strings.Join(text, " "), "message") {
									found = append(found, finding.RuleID)
								}
								for _, id := range want {
									if !slices.Contains(found, id) {
										t.Errorf("hook scan on %q found %v; missed b's blocking rule %s", scope, found, id)
									}
								}
							}
						})
					}
				}
			}
		}
	}
}
