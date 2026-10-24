// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// Review of r104 Q-identity (rc.7, loop round 1): /api/v1/inspect/tool
// applies the mode of the gateway's own connector to a credential not
// scoped to one, but the profile was decided for the global settings. Of
// two proven assignments, one acting for OpenClaw and observing globally,
// the other acting globally and observing OpenClaw, the second covers the
// first globally, so it applied, and OpenClaw's tool call was allowed
// where the first profile blocks it. The whole decision is now taken for
// the connector whose mode the verdict takes.
func TestInspectToolDecidesTheProfileForItsOwnConnector(t *testing.T) {
	resetConnectorRuleCategories(t)
	withLocalPatternsRestored(t)
	priorManaged := ManagedEnterpriseActive()
	setManagedEnterpriseRedactionPosture(false)
	t.Cleanup(func() { setManagedEnterpriseRedactionPosture(priorManaged) })
	previous := liveGuardrailProfiles.Load()
	t.Cleanup(func() { liveGuardrailProfiles.Store(previous) })
	stubProfileSources(t)
	p := identityTestPlatforms[0]
	member := identityTestSubject(p, p.providers[1], stateProven, true)
	profiles := map[string]config.GuardrailProfile{
		"openclaw-acts": {Mode: "observe", Connectors: map[string]config.PerConnectorGuardrailConfig{"openclaw": {Mode: "action"}}},
		"global-acts":   {Mode: "action", Connectors: map[string]config.PerConnectorGuardrailConfig{"openclaw": {Mode: "observe"}}},
		"watch":         {Mode: "observe"},
	}
	const secret = `{"tool":"message","args":{"to":"+1234"},"content":"Your key is sk-ant-api03-A7b9C2d4E6f8G1h3J5k7L9m2","direction":"outbound"}`
	for _, tc := range []struct {
		name   string
		order  []string
		scoped string
		block  bool
	}{
		{name: "the first acts for OpenClaw, the second globally", order: []string{"openclaw-acts", "global-acts"}, block: true},
		{name: "the first acts globally, the second for OpenClaw", order: []string{"global-acts", "openclaw-acts"}, block: true},
		{name: "no matching profile acts for OpenClaw", order: []string{"watch", "global-acts"}},
		{name: "one profile, acting for OpenClaw alone", order: []string{"openclaw-acts"}, block: true},
		{name: "one profile, acting globally but observing OpenClaw", order: []string{"global-acts"}},
		{name: "a scoped credential keeps its own connector", order: []string{"openclaw-acts", "global-acts"}, scoped: "codex", block: true},
		{name: "a scoped credential for OpenClaw", order: []string{"global-acts", "openclaw-acts"}, scoped: "openclaw", block: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "observe"
			cfg.Guardrail.Connector = "openclaw"
			cfg.Guardrail.Profiles = profiles
			for _, name := range tc.order {
				cfg.Guardrail.ProfileAssignments = append(cfg.Guardrail.ProfileAssignments,
					config.ProfileAssignment{Profile: name, Match: config.ProfileMatch{Groups: []string{p.group}}})
			}
			cfg.Guardrail.DefaultProfile = "watch"
			api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, nil, nil, cfg)
			api.inspectToolScanTimeout = 5 * time.Second
			req := httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool", strings.NewReader(secret))
			ctx := context.WithValue(req.Context(), testVerifiedSubjectKey{}, member)
			if tc.scoped != "" {
				ctx = withAuthenticatedInspectConnector(ctx, tc.scoped)
			}
			rec := httptest.NewRecorder()
			api.guardrailProfileInspectMiddleware(http.HandlerFunc(api.handleInspectTool)).ServeHTTP(rec, req.WithContext(ctx))
			var verdict ToolInspectVerdict
			if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &verdict) != nil {
				t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
			}
			if len(verdict.Findings) == 0 {
				t.Fatalf("no finding for the secret: %+v", verdict)
			}
			if (verdict.Action == "block") != tc.block {
				t.Fatalf("verdict %+v; want block %t", verdict, tc.block)
			}
		})
	}
}

// Review of r104 Q-identity (rc.7, loop round 1): the meet of profiles took
// the lowest block level of every member that blocks on any surface and
// applied it to both. With a member whose hooks act at CRITICAL and one that
// only inspects in action mode at LOW, a MEDIUM hook finding was blocked
// though no member blocks it. Each surface now takes its block levels and
// HILT only from the members that enforce on it: on every surface, for
// every connector and severity, the meet blocks exactly where one of its
// members does.
func TestMeetTakesEachSurfacesBlockLevelFromItsEnforcers(t *testing.T) {
	codex := func(mode, blockAt string) map[string]config.PerConnectorGuardrailConfig {
		return map[string]config.PerConnectorGuardrailConfig{"codex": {Mode: mode, BlockAt: blockAt}}
	}
	type surface struct {
		name    string
		surface profileSurfaces
		mode    func(*config.Config, string) string
	}
	surfaces := []surface{
		{"hooks", profileSurfaceHooks, hookModeForConfig},
		{"inspect", profileSurfaceInspect, inspectMode},
	}
	for _, tc := range []struct {
		name     string
		base     func(*config.Config)
		profiles map[string]config.GuardrailProfile
	}{
		{name: "hooks act at CRITICAL, the other member only inspects in action mode at LOW", base: func(c *config.Config) {
			c.Guardrail.Mode, c.Codex.Mode = "action", "observe"
		}, profiles: map[string]config.GuardrailProfile{
			"a": {Connectors: codex("action", "CRITICAL")},
			"b": {BlockAt: "LOW"},
		}},
		{name: "hooks act at LOW in a member that observes inspect, the other acts at HIGH", base: func(c *config.Config) {
			c.Guardrail.Mode, c.Codex.Mode = "observe", "action"
		}, profiles: map[string]config.GuardrailProfile{
			"a": {BlockAt: "LOW"},
			"b": {Connectors: codex("action", "HIGH")},
		}},
		{name: "a member acts for Codex at MEDIUM, the other globally at LOW but observes Codex", profiles: map[string]config.GuardrailProfile{
			"a": {Connectors: codex("action", "MEDIUM")},
			"b": {Mode: "action", BlockAt: "LOW", Connectors: codex("observe", "")},
		}},
		{name: "connector hooks act, the other member inspects", base: func(c *config.Config) {
			c.Guardrail.Mode = "action"
			c.ConnectorHooks = map[string]config.AgentHookConfig{"hermes": {Enabled: true, Mode: "observe"}}
		}, profiles: map[string]config.GuardrailProfile{
			"a": {BlockAt: "LOW"},
			"b": {Connectors: map[string]config.PerConnectorGuardrailConfig{"hermes": {Mode: "action", BlockAt: "CRITICAL"}}},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := identityTestPlatforms[0]
			profiles := map[string]config.GuardrailProfile{"watch": {Mode: "observe"}}
			for name, profile := range tc.profiles {
				profiles[name] = profile
			}
			set := surfaceModesSet(t, tc.base, "watch", profiles,
				config.ProfileAssignment{Profile: "a", Match: config.ProfileMatch{Groups: []string{p.group}}},
				config.ProfileAssignment{Profile: "b", Match: config.ProfileMatch{Groups: []string{p.group}}})
			stubProfileSources(t)
			ctx := context.WithValue(t.Context(), testVerifiedSubjectKey{}, identityTestSubject(p, p.providers[1], stateProven, true))
			members := []string{"a", "b"}
			meets := 0
			for _, connectorName := range []string{"codex", "hermes", "claudecode", ""} {
				for _, s := range surfaces {
					// A request of the surface, as its entry point resolves it.
					resolved := resolvedGuardrailProfileFrom(withGuardrailProfile(withProfileSurface(ctx, s.surface), set, connectorName))
					if resolved == nil || resolved.derived == nil {
						t.Fatalf("request for %q on the %s: no profile resolved", connectorName, s.name)
					}
					if !config.IsProfileMeet(resolved.decision.Name) {
						continue // one member covers the other: it applies as it is
					}
					meets++
					meet := resolved.derived
					for _, c := range append(set.meetConnectors(), "") {
						for _, severity := range []string{"LOW", "MEDIUM", "HIGH", "CRITICAL"} {
							want := false
							for _, member := range members {
								cfg := set.profileConfig(member)
								want = want || s.mode(cfg, c) == "action" && guardrailActionForConnector(cfg, c, severity, false) == guardrailActionBlock
							}
							got := s.mode(meet, c) == "action" && guardrailActionForConnector(meet, c, severity, false) == guardrailActionBlock
							if got != want {
								t.Errorf("request for %q: the meet on the %s of %q blocks %s: %t; a member blocks it: %t", connectorName, s.name, c, severity, got, want)
							}
						}
					}
				}
			}
			if meets == 0 {
				t.Fatal("no request resolved a meet of the two profiles")
			}
		})
	}
}

// The entry points mark the surface whose meet a request applies: the
// inspect endpoints and the proxy inspect, the agent hooks hook, and ACP,
// unmarked, applies the meet of every surface.
func TestProfileSurfaceMarks(t *testing.T) {
	if got := profileSurfaceFrom(t.Context()); got != profileSurfacesAll {
		t.Fatalf("an unmarked request applies %v; want every surface", got)
	}
	api := &APIServer{}
	var got profileSurfaces
	api.guardrailProfileInspectMiddleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = profileSurfaceFrom(r.Context())
	})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool", nil))
	if got != profileSurfaceInspect {
		t.Fatalf("the inspect middleware marks %v; want inspect", got)
	}
}
