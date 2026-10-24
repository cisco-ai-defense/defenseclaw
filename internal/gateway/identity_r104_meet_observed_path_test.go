// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// An uncertain profile that only observes a request's path cannot change
// that request's decision, so its unconfirmed fact does not refuse it (loop
// round 2 review). Profile a, proven by UID, acts on both paths from HIGH.
// Profile b, which an unconfirmed account name may select, inherits the
// machine's modes, so it acts on one path only, either with another pack
// ("other pack") or from LOW on a's pack ("lower level"). A request on the
// path b observes gets a, in both assignment orders, on the decision and on
// the real hook and inspect routes. A request on the path b acts on, and
// explain, which decides no single path, keep b's missing fact: refused.
func TestUncertainProfileObservingTheRequestsPathDoesNotRefuseIt(t *testing.T) {
	stubProfileSources(t)
	for _, setup := range []struct {
		name                  string
		inspectMode, hookMode string
		bActsOnHook, samePack bool
	}{
		{name: "hook observed/other pack", inspectMode: "action", hookMode: "observe"},
		{name: "hook observed/lower level", inspectMode: "action", hookMode: "observe", samePack: true},
		{name: "inspect observed/other pack", inspectMode: "observe", hookMode: "action", bActsOnHook: true},
		{name: "inspect observed/lower level", inspectMode: "observe", hookMode: "action", bActsOnHook: true, samePack: true},
	} {
		for _, first := range []string{"uid", "name"} {
			t.Run(setup.name+"/"+first+" first", func(t *testing.T) {
				root := t.TempDir()
				packA, packB, bBlock := meetRulePackDir(t, root, "OBS-A"), "", "HIGH"
				if setup.samePack {
					packB, bBlock = packA, "LOW"
				} else {
					packB = meetRulePackDir(t, root, "OBS-B")
				}
				cfg := &config.Config{}
				cfg.Guardrail.Mode = setup.inspectMode
				cfg.Guardrail.Connector = "codex"
				cfg.Codex.Mode = setup.hookMode
				cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
					"a": {Mode: "action", BlockAt: "HIGH", RulePackDir: packA},
					"b": {BlockAt: bBlock, RulePackDir: packB},
				}
				p := identityTestPlatforms[0]
				byUID := config.ProfileAssignment{Profile: "a", Match: config.ProfileMatch{Users: []string{p.id}}}
				byName := config.ProfileAssignment{Profile: "b", Match: config.ProfileMatch{Users: []string{`.\` + p.name}}}
				cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{byUID, byName}
				if first == "name" {
					cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{byName, byUID}
				}
				set := newGuardrailProfileSetFor(t, cfg)
				for _, scope := range []string{"", "codex"} {
					set.rules[effectiveRulePackKey(set.profiles["a"].Config, scope)] = meetPathGeneration(t, "OBS-A")
					if !setup.samePack {
						set.rules[effectiveRulePackKey(set.profiles["b"].Config, scope)] = meetPathGeneration(t, "OBS-B")
					}
				}
				set.missing = nil
				aCfg, bCfg := set.profileConfig("a"), set.profileConfig("b")
				if !configBlocksOn(aCfg, "codex", profilePathHook) || !configBlocksOn(aCfg, "codex", profilePathInspect) ||
					configBlocksOn(bCfg, "codex", profilePathHook) != setup.bActsOnHook ||
					configBlocksOn(bCfg, "codex", profilePathInspect) == setup.bActsOnHook {
					t.Fatalf("fixture: a must act on both paths and b on the hook path %v only", setup.bActsOnHook)
				}
				subject := identityTestSubject(p, p.providers[0], stateProven, true)
				subject.holderUnproven = true
				api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
				api.guardrailProfiles.set.Store(set)
				base := context.WithValue(t.Context(), testVerifiedSubjectKey{}, subject)

				refused := func(decision profileDecision) bool {
					return decision.Refused != "" && slices.Contains(decision.Unproven, "account:unknown")
				}
				for _, path := range []struct {
					name      string
					ctx       context.Context
					bObserves bool
				}{
					{"hook", api.withGuardrailProfileDecision(withProfilePath(base, profilePathHook), "codex"), !setup.bActsOnHook},
					{"inspect", api.withGuardrailProfileDecision(context.WithValue(base, profileRuleScanConnectorKey{}, "codex"), ""), setup.bActsOnHook},
				} {
					resolved := resolvedGuardrailProfileFrom(path.ctx)
					if resolved == nil {
						t.Fatalf("%s: no decision", path.name)
					}
					if path.bObserves {
						if resolved.decision.Refused != "" || resolved.decision.Name != "a" {
							t.Errorf("%s: decision %+v; want a, not refused (b only observes this path)", path.name, resolved.decision)
						}
					} else if !refused(resolved.decision) {
						t.Errorf("%s: decision %+v; want refused for the unconfirmed account (b acts on this path)", path.name, resolved.decision)
					}
				}
				// Explain decides no single path: b may change it.
				if explained := set.matchAgent(&subject, profileSubjectVerified, "codex", []string{"codex"}, profilePathAny, "", nil); !refused(explained) {
					t.Errorf("explain: decision %+v; want refused for the unconfirmed account", explained)
				}

				// The real routes, twice each: an uncertain decision is never
				// memoised, and a covered one never answers the other path.
				for range 2 {
					for _, content := range []struct {
						text  string
						block bool
					}{{meetPlainMarker("OBS-A"), true}, {meetMediumMarker("OBS-A"), false}} {
						hook := fmt.Sprintf(`{"session_id":"obs-session","hook_event_name":"UserPromptSubmit","prompt":"%s"}`, content.text)
						req := httptest.NewRequest(http.MethodPost, "/api/v1/codex/hook", strings.NewReader(hook)).WithContext(base)
						setTestCodexHookBinding(req, "UserPromptSubmit", defaultTestCodexHookContract)
						rec := httptest.NewRecorder()
						api.handleAgentHook("codex").ServeHTTP(rec, req)
						body := rec.Body.String()
						if setup.bActsOnHook {
							if !strings.Contains(body, "DefenseClaw refused this request: the account holder is unconfirmed") {
								t.Errorf("hook %s: %d %.400s; want the refusal", content.text, rec.Code, body)
							}
						} else if got := strings.HasPrefix(body, `{"action":"block"`); rec.Code != http.StatusOK || got != content.block || strings.Contains(body, "refused this request") {
							t.Errorf("hook %s: %d %.400s; want a's decision, block %v", content.text, rec.Code, body, content.block)
						}

						inspect := fmt.Sprintf(`{"tool":"message","content":"%s"}`, content.text)
						req = httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool", strings.NewReader(inspect)).WithContext(base)
						rec = httptest.NewRecorder()
						api.guardrailProfileInspectMiddleware(http.HandlerFunc(api.handleInspectTool)).ServeHTTP(rec, req)
						body = rec.Body.String()
						if !setup.bActsOnHook {
							if !strings.Contains(body, "refused this request") {
								t.Errorf("inspect %s: %d %.400s; want the refusal", content.text, rec.Code, body)
							}
						} else if got := strings.Contains(body, `"action":"block"`); rec.Code != http.StatusOK || got != content.block || strings.Contains(body, "refused this request") {
							t.Errorf("inspect %s: %d %.400s; want a's decision, block %v", content.text, rec.Code, body, content.block)
						}
					}
				}
			})
		}
	}
}

// A covered decision is memoised per request path: the key of one path
// never answers another.
func TestProfileMatchKeyNamesTheRequestPath(t *testing.T) {
	subject := &profileSubject{UserID: "1000", UserName: "alice"}
	keys := map[[32]byte]profilePath{}
	for _, path := range profilePaths {
		key := profileMatchKey(subject, profileSubjectVerified, "codex", []string{"codex"}, path, "")
		if other, seen := keys[key]; seen {
			t.Fatalf("paths %d and %d share a memo key", other, path)
		}
		keys[key] = path
	}
}
