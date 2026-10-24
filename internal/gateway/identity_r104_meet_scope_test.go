// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// profileScopeRequest is one way a request reaches a profile decision: the
// connector it authenticated for (hook or inspect credential), the inspect
// route it called, or neither.
type profileScopeRequest struct {
	name          string
	hook, inspect string // authenticated hook or inspect connector
	path          string // inspect route through the inspect middleware; "" resolves without it
}

var profileScopeRequests = []profileScopeRequest{
	{name: "Codex hook", hook: "codex"},
	{name: "Claude Code hook", hook: "claudecode"},
	{name: "unscoped tool inspect", path: "/api/v1/inspect/tool"},
	{name: "unscoped prompt inspect", path: "/api/v1/inspect/request"},
	{name: "Codex-scoped tool inspect", inspect: "codex", path: "/api/v1/inspect/tool"},
	{name: "Claude Code-scoped tool inspect", inspect: "claudecode", path: "/api/v1/inspect/tool"},
	{name: "unscoped decision without a route", path: ""},
}

// resolveProfileScope resolves rq on api as the gateway does and returns the
// decision and the connector its scans read.
func resolveProfileScope(t *testing.T, api *APIServer, ctx context.Context, rq profileScopeRequest) (profileDecision, string) {
	t.Helper()
	ctx = withAuthenticatedHookConnector(ctx, rq.hook)
	ctx = withAuthenticatedInspectConnector(ctx, rq.inspect)
	if rq.hook != "" {
		ctx = api.withGuardrailProfileDecision(ctx, rq.hook)
		return resolvedGuardrailProfileFrom(ctx).decision, profileRequestConnector(ctx)
	}
	if rq.path == "" {
		ctx = api.withGuardrailProfileDecision(ctx, "")
		return resolvedGuardrailProfileFrom(ctx).decision, profileRequestConnector(ctx)
	}
	var decision profileDecision
	var scan string
	req := httptest.NewRequest(http.MethodPost, rq.path, nil).WithContext(ctx)
	api.guardrailProfileInspectMiddleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		decision, scan = resolvedGuardrailProfileFrom(r.Context()).decision, profileRequestConnector(r.Context())
		if rq.hook == "" && rq.inspect == "" {
			if id, _ := requestAgentIdentity(r.Context()); id != "" {
				t.Errorf("%s derived agent identity %q for a connector it did not authenticate for", rq.name, id)
			}
		}
	})).ServeHTTP(httptest.NewRecorder(), req)
	return decision, scan
}

// A connector assignment applies to the connector a request authenticated
// for or the hook route it reached, never to the gateway's configured
// connector inferred for an unscoped credential. Scans of that unscoped
// tool inspect still read the gateway connector's rules and settings.
func TestConnectorAssignmentMatchesOnlyARecordedConnector(t *testing.T) {
	stubProfileSources(t)
	for _, tc := range []struct {
		assigned, fallback string
	}{
		{assigned: "watch", fallback: "strict"},
		{assigned: "strict", fallback: "watch"},
	} {
		t.Run(tc.assigned+" assigned to Codex", func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = "codex"
			cfg.Guardrail.DefaultProfile = tc.fallback
			cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
				"strict": {Mode: "action", BlockAt: "LOW"},
				"watch":  {Mode: "observe", BlockAt: "CRITICAL"},
			}
			cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
				{Profile: tc.assigned, Match: config.ProfileMatch{Connectors: []string{"codex"}}},
			}
			set, err := newGuardrailProfileSet(cfg, nil, true)
			if err != nil {
				t.Fatal(err)
			}
			api := &APIServer{scannerCfg: cfg}
			api.guardrailProfiles.set.Store(set)
			p := identityTestPlatforms[0]
			ctx := context.WithValue(t.Context(), testVerifiedSubjectKey{}, identityTestSubject(p, p.providers[0], stateProven, true))
			want := map[string]struct{ profile, scan string }{
				"Codex hook":                        {tc.assigned, "codex"},
				"Claude Code hook":                  {tc.fallback, "claudecode"},
				"unscoped tool inspect":             {tc.fallback, "codex"},
				"unscoped prompt inspect":           {tc.fallback, ""},
				"Codex-scoped tool inspect":         {tc.assigned, "codex"},
				"Claude Code-scoped tool inspect":   {tc.fallback, "claudecode"},
				"unscoped decision without a route": {tc.fallback, ""},
			}
			for _, rq := range profileScopeRequests {
				decision, scan := resolveProfileScope(t, api, ctx, rq)
				w := want[rq.name]
				if decision.Name != w.profile || decision.Refused != "" {
					t.Errorf("%s: decision %+v; want profile %q", rq.name, decision, w.profile)
				}
				if scan != w.scan {
					t.Errorf("%s: scans connector %q; want %q", rq.name, scan, w.scan)
				}
			}
		})
	}
}

// A meet whose members' rules together exceed the semantic rule limit of one
// generation on one scope refuses no request, whatever scope it scans: each
// member's rules are scanned as that member scans them.
func TestMeetOverTheLimitOnOneScopeRefusesNoRequest(t *testing.T) {
	stubProfileSources(t)
	for _, failing := range []string{"", "codex", "claudecode"} {
		t.Run("over the limit on scope "+failing, func(t *testing.T) {
			root := t.TempDir()
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = "codex"
			cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
				"a": {Mode: "action", BlockAt: "HIGH", RulePackDir: meetRulePackDir(t, root, "SCOPE-GLOBAL-A"),
					Connectors: map[string]config.PerConnectorGuardrailConfig{
						"codex":      {RulePackDir: meetRulePackDir(t, root, "SCOPE-CODEX-A")},
						"claudecode": {RulePackDir: meetRulePackDir(t, root, "SCOPE-CLAUDE-A")},
					}},
				"b": {Mode: "action", BlockAt: "MEDIUM", RulePackDir: meetRulePackDir(t, root, "SCOPE-GLOBAL-B"),
					Connectors: map[string]config.PerConnectorGuardrailConfig{
						"codex":      {RulePackDir: meetRulePackDir(t, root, "SCOPE-CODEX-B")},
						"claudecode": {RulePackDir: meetRulePackDir(t, root, "SCOPE-CLAUDE-B")},
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
			set.rules[effectiveRulePackKey(set.profiles["a"].Config, failing)] = meetSemanticGeneration(t, "SCOPE-A", 2)
			set.rules[effectiveRulePackKey(set.profiles["b"].Config, failing)] = meetSemanticGeneration(t, "SCOPE-B", maxGenerationSemanticRules-1)
			api := &APIServer{scannerCfg: cfg}
			api.guardrailProfiles.set.Store(set)
			ctx := context.WithValue(t.Context(), testVerifiedSubjectKey{}, identityTestSubject(p, p.providers[0], stateProven, true))
			meetName := config.ProfileMeetName([]string{"a", "b"})
			for _, scope := range []string{"", "codex", "claudecode"} {
				if generation := set.meet(meetName).ruleGeneration(ctx, set, scope); generation == nil || len(generation.members) != 2 {
					t.Fatalf("scope %q: meet generation %+v; want both members' rules", scope, generation)
				}
			}
			for _, rq := range profileScopeRequests {
				decision, _ := resolveProfileScope(t, api, ctx, rq)
				if decision.Name != meetName || decision.Refused != "" {
					t.Errorf("%s: decision %+v; want the meet, never refused", rq.name, decision)
				}
			}
		})
	}
}

// Per connector, the meet of two profiles keeps each member's hook mode and
// inspect mode apart: a hook-only action stays hook-only, an inspect-only
// action stays inspect-only, and a connector whose hook mode only
// connector_hooks sets keeps it.
func TestProfileMeetModesPerConnector(t *testing.T) {
	stubProfileSources(t)
	root := t.TempDir()
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Connector = "codex"
	cfg.Codex.Mode = "action"
	cfg.ClaudeCode.Mode = "observe"
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{"claudecode": {Mode: "action"}}
	cfg.ConnectorHooks = map[string]config.AgentHookConfig{"zzplugin": {Mode: "action"}}
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"a": {RulePackDir: meetRulePackDir(t, root, "PER-A")},
		"b": {RulePackDir: meetRulePackDir(t, root, "PER-B")},
	}
	set, err := newGuardrailProfileSet(cfg, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	name, single := set.meetOf([]string{"a", "b"}, set.profileCoverConnectors("codex"))
	if single || !config.IsProfileMeet(name) {
		t.Fatalf("selection = %q, single %v; want a meet", name, single)
	}
	derived, ok := set.derivedProfile(name)
	if !ok {
		t.Fatal("meet did not derive")
	}
	for _, tc := range []struct{ connector, hook, inspect string }{
		{"codex", "action", "observe"},
		{"claudecode", "observe", "action"},
		{"zzplugin", "action", "observe"},
	} {
		for _, member := range []string{"a", "b"} {
			m := set.profileConfig(member)
			if hookModeForConfig(m, tc.connector) != tc.hook || inspectMode(m, tc.connector) != tc.inspect {
				t.Fatalf("fixture: member %s on %s hook %q inspect %q", member, tc.connector,
					hookModeForConfig(m, tc.connector), inspectMode(m, tc.connector))
			}
		}
		if got := hookModeForConfig(derived.Config, tc.connector); got != tc.hook {
			t.Errorf("%s hook mode under the meet = %q, want %q", tc.connector, got, tc.hook)
		}
		if got := inspectMode(derived.Config, tc.connector); got != tc.inspect {
			t.Errorf("%s inspect mode under the meet = %q, want %q", tc.connector, got, tc.inspect)
		}
	}
}
