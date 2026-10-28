// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// A member of a strictest combination that acts on one path never blocks
// on the other, on any route of that path (W25-ident loop round 1). Profile
// a sets no mode and blocks from MEDIUM with its own pack; b acts on both
// paths from HIGH with another pack. In "hook only" the machine's Codex
// hook acts and inspect observes, so a acts on the Codex hook only; in
// "inspect only" the reverse. Every inspect route (tool, request, response,
// tool-response), unscoped and with a Codex inspect credential, blocks a's
// marker only where a acts on inspect, and b's HIGH marker always. B's
// MEDIUM marker alerts under its own threshold; the Codex hook route, for UserPromptSubmit and
// PreToolUse, only where a acts on the hook.
func TestMeetMemberActsOnlyOnItsOwnPathOnEveryRoute(t *testing.T) {
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
					"a": {BlockAt: "MEDIUM", RulePackDir: meetRulePackDir(t, root, "ROUTE-A")},
					"b": {Mode: "action", BlockAt: "HIGH", RulePackDir: meetRulePackDir(t, root, "ROUTE-B")},
				}
				p := identityTestPlatforms[0]
				second := map[string]string{"a": "b", "b": "a"}[first]
				cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
					{Profile: first, Match: config.ProfileMatch{Users: []string{p.id}}},
					{Profile: second, Match: config.ProfileMatch{Groups: []string{p.group}}},
				}
				set, err := newGuardrailProfileSet(cfg, nil, true)
				if err != nil {
					t.Fatal(err)
				}
				for _, scope := range []string{"", "codex"} {
					set.rules[effectiveRulePackKey(set.profiles["a"].Config, scope)] = meetPathGeneration(t, "ROUTE-A")
					set.rules[effectiveRulePackKey(set.profiles["b"].Config, scope)] = meetPathGeneration(t, "ROUTE-B")
				}
				set.missing = nil
				api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
				api.guardrailProfiles.set.Store(set)
				subject := context.WithValue(t.Context(), testVerifiedSubjectKey{}, identityTestSubject(p, p.providers[0], stateProven, true))
				meetName := config.ProfileMeetName([]string{"a", "b"})

				markers := []struct {
					text string
					name string
				}{
					{meetPlainMarker("ROUTE-A"), "a's HIGH marker"},
					{meetMediumMarker("ROUTE-B"), "b's MEDIUM marker"},
					{meetPlainMarker("ROUTE-B"), "b's HIGH marker"},
				}
				quoted := func(s string) string {
					raw, _ := json.Marshal(s)
					return string(raw)
				}
				routes := []struct {
					path    string
					handler http.HandlerFunc
					body    func(string) string
				}{
					{"/api/v1/inspect/tool", api.handleInspectTool, func(s string) string {
						return fmt.Sprintf(`{"tool":"message","content":%s}`, quoted(s))
					}},
					{"/api/v1/inspect/request", api.handleInspectRequest, func(s string) string {
						return fmt.Sprintf(`{"content":%s}`, quoted(s))
					}},
					{"/api/v1/inspect/response", api.handleInspectResponse, func(s string) string {
						return fmt.Sprintf(`{"content":%s}`, quoted(s))
					}},
					{"/api/v1/inspect/tool-response", api.handleInspectToolResponse, func(s string) string {
						return fmt.Sprintf(`{"tool":"shell","output":%s}`, quoted(s))
					}},
				}
				for _, credential := range []string{"", "codex"} {
					for _, route := range routes {
						for _, marker := range markers {
							want := marker.text == meetPlainMarker("ROUTE-B") ||
								marker.text == meetPlainMarker("ROUTE-A") && setup.aInspect
							ctx := subject
							if credential != "" {
								ctx = withAuthenticatedInspectConnector(ctx, credential)
							}
							req := httptest.NewRequest(http.MethodPost, route.path, strings.NewReader(route.body(marker.text))).WithContext(ctx)
							rec := httptest.NewRecorder()
							var seen *resolvedGuardrailProfile
							api.guardrailProfileInspectMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
								seen = resolvedGuardrailProfileFrom(r.Context())
								route.handler(w, r)
							})).ServeHTTP(rec, req)
							// On an unscoped prompt or response inspect the global
							// scope may be covered by b alone.
							wantName := meetName
							if credential == "" && route.path != "/api/v1/inspect/tool" && !setup.aInspect {
								wantName = "b"
							}
							if seen == nil || seen.decision.Name != wantName || seen.decision.Refused != "" {
								t.Fatalf("%s (credential %q): decision %+v; want %s", route.path, credential, seen, wantName)
							}
							if got := strings.Contains(rec.Body.String(), `"action":"block"`); rec.Code != http.StatusOK || got != want {
								t.Errorf("%s (credential %q) %s: %d %.300s; want block %v", route.path, credential, marker.name, rec.Code, rec.Body.String(), want)
							}
						}
					}
				}

				for _, event := range []struct {
					name string
					body func(string) string
				}{
					{"UserPromptSubmit", func(s string) string {
						return fmt.Sprintf(`{"session_id":"route-session","hook_event_name":"UserPromptSubmit","prompt":%s}`, quoted(s))
					}},
				} {
					for _, marker := range markers {
						want := marker.text == meetPlainMarker("ROUTE-B") ||
							marker.text == meetPlainMarker("ROUTE-A") && setup.aHook
						req := httptest.NewRequest(http.MethodPost, "/api/v1/codex/hook", strings.NewReader(event.body(marker.text))).WithContext(subject)
						setTestCodexHookBinding(req, event.name, defaultTestCodexHookContract)
						rec := httptest.NewRecorder()
						api.handleAgentHook("codex").ServeHTTP(rec, req)
						if got := strings.HasPrefix(rec.Body.String(), `{"action":"block"`); rec.Code != http.StatusOK || got != want {
							t.Errorf("hook %s %s: %d %.300s; want block %v", event.name, marker.name, rec.Code, rec.Body.String(), want)
						}
					}
				}
			})
		}
	}
}
