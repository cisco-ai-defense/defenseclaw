// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/agentidentity"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

// unprovenReason is how a decision that needs unproven facts names them:
// its refusal under strict, else the applied decision's Uncertain.
func unprovenReason(d profileDecision) string {
	if d.Refused != "" {
		return d.Refused
	}
	return d.Uncertain
}

// strictTier puts p under tier: "strict" is action mode with the built-in
// strict rule pack (loaded from the repository's policies, set as cfg's
// policy_dir), any other value is p's mode.
func strictTier(t testing.TB, cfg *config.Config, p config.GuardrailProfile, tier string) config.GuardrailProfile {
	t.Helper()
	if tier != "strict" {
		p.Mode = tier
		return p
	}
	dir, err := filepath.Abs(filepath.Join("..", "..", "policies"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.PolicyDir = dir
	p.Mode, p.RulePack = "action", "strict"
	return p
}

// observeUncertainSet is a profile set whose default, watch, only
// observes, with candidate profiles that observe, block in action mode
// (by their mode or a per-connector mode), block under strict (action with
// the strict rule pack), or add a sandbox section. globalStrict makes the
// strict pack the configuration's own, which every profile inherits.
func observeUncertainSet(t *testing.T, globalStrict bool, assignments ...config.ProfileAssignment) *guardrailProfileSet {
	t.Helper()
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	strictTier(t, cfg, config.GuardrailProfile{}, "strict")
	if globalStrict {
		cfg.Guardrail.RulePack = "strict"
	}
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"watch":          {Mode: "observe"},
		"legacy-watch":   {Mode: "observe", BlockAt: "LOW"},
		"action":         {Mode: "action", BlockAt: "LOW"},
		"strict":         {Mode: "action", BlockAt: "LOW", RulePack: "strict"},
		"strict-observe": {Mode: "observe", RulePack: "strict"},
		"codex-action":   {Mode: "observe", Connectors: map[string]config.PerConnectorGuardrailConfig{"codex": {Mode: "action"}}},
		"codex-strict":   {Mode: "observe", Connectors: map[string]config.PerConnectorGuardrailConfig{"codex": {Mode: "action", RulePack: "strict"}}},
		"sandboxed":      {Mode: "observe", Sandbox: &config.OpenShellAdminConfig{RequiredFor: []string{"codex"}}},
	}
	cfg.Guardrail.ProfileAssignments = assignments
	cfg.Guardrail.DefaultProfile = "watch"
	set, err := newGuardrailProfileSet(cfg, nil, true)
	if err != nil || set == nil {
		t.Fatalf("profile set: %v", err)
	}
	return set
}

// Review of r104 Q-identity (continuation 3, loop round 3, and
// continuation 4, loop round 1; OVERTIGHT-AUDIT item 11, GAP-0653): a
// decision that needs an unproven fact (an agents entry the upgrade owner
// map has not bound, groups an SSSD outage or an unprivileged lookup cannot
// confirm, a UPN the guardian has not written) refused every hook, inspect
// and proxy request whenever a profile that may apply was in action mode or
// had a sandbox section, so an observe default with a sandboxed or
// action-mode assignment hard-blocked all work. The strictest combination
// of every profile that may apply now decides the request in its own mode,
// with the missing facts named (Uncertain); only strict (a candidate in
// action mode with the strict rule pack, the profile's own, a
// per-connector one, or inherited) refuses.
func TestUncertainDecisionAppliesTheStrictestCandidateInItsOwnMode(t *testing.T) {
	p := identityTestPlatforms[0]
	const legacy = "agt-00000000000000aa"
	unresolved := func(entry string) bool { return entry == legacy }
	proven := identityTestSubject(p, p.providers[1], stateProven, false)
	groupsUnknown := identityTestSubject(p, p.providers[1], stateGroupsUnknown, false)
	upnUnknown := proven
	upnUnknown.upnUnproven = true
	agent := config.ProfileMatch{Agents: []string{legacy}}
	groups := config.ProfileMatch{Groups: []string{p.group}}
	upn := config.ProfileMatch{Users: []string{"alice@corp.example"}}
	for _, tc := range []struct {
		name         string
		subject      profileSubject
		unresolved   func(string) bool
		match        config.ProfileMatch
		profile      string
		connector    string
		globalStrict bool
		fact         string
		// want is the mode the request is decided in, or "refused".
		want    string
		sandbox bool
	}{
		{name: "agent entry, both observe", subject: proven, unresolved: unresolved, match: agent, profile: "legacy-watch", connector: "codex", fact: "agent:unknown", want: "observe"},
		{name: "agent entry in action mode", subject: proven, unresolved: unresolved, match: agent, profile: "action", connector: "codex", fact: "agent:unknown", want: "action"},
		{name: "agent entry under strict", subject: proven, unresolved: unresolved, match: agent, profile: "strict", connector: "codex", fact: "agent:unknown", want: "refused"},
		{name: "agent entry with the strict pack in observe mode", subject: proven, unresolved: unresolved, match: agent, profile: "strict-observe", connector: "codex", fact: "agent:unknown", want: "observe"},
		{name: "agent entry in action mode, strict pack inherited", subject: proven, unresolved: unresolved, match: agent, profile: "action", connector: "codex", globalStrict: true, fact: "agent:unknown", want: "refused"},
		{name: "agent entry observes, strict pack inherited", subject: proven, unresolved: unresolved, match: agent, profile: "legacy-watch", connector: "codex", globalStrict: true, fact: "agent:unknown", want: "observe"},
		{name: "agent entry in action mode for this connector", subject: proven, unresolved: unresolved, match: agent, profile: "codex-action", connector: "codex", fact: "agent:unknown", want: "action"},
		{name: "agent entry strict for this connector", subject: proven, unresolved: unresolved, match: agent, profile: "codex-strict", connector: "codex", fact: "agent:unknown", want: "refused"},
		{name: "agent entry in action mode for another connector only", subject: proven, unresolved: unresolved, match: agent, profile: "codex-action", connector: "hermes", fact: "agent:unknown", want: "observe"},
		{name: "agent entry strict for another connector only", subject: proven, unresolved: unresolved, match: agent, profile: "codex-strict", connector: "hermes", fact: "agent:unknown", want: "observe"},
		{name: "agent entry has a sandbox section", subject: proven, unresolved: unresolved, match: agent, profile: "sandboxed", connector: "codex", fact: "agent:unknown", want: "observe", sandbox: true},
		{name: "groups unknown, both observe", subject: groupsUnknown, match: groups, profile: "legacy-watch", connector: "codex", fact: "groups:unknown", want: "observe"},
		{name: "groups unknown, group profile in action mode", subject: groupsUnknown, match: groups, profile: "action", connector: "codex", fact: "groups:unknown", want: "action"},
		{name: "groups unknown, group profile has a sandbox section", subject: groupsUnknown, match: groups, profile: "sandboxed", connector: "codex", fact: "groups:unknown", want: "observe", sandbox: true},
		{name: "groups unknown, group profile under strict", subject: groupsUnknown, match: groups, profile: "strict", connector: "codex", fact: "groups:unknown", want: "refused"},
		{name: "UPN unknown, both observe", subject: upnUnknown, match: upn, profile: "legacy-watch", connector: "codex", fact: "upn:unknown", want: "observe"},
		{name: "UPN unknown, user profile in action mode", subject: upnUnknown, match: upn, profile: "action", connector: "codex", fact: "upn:unknown", want: "action"},
		{name: "UPN unknown, user profile under strict", subject: upnUnknown, match: upn, profile: "strict", connector: "codex", fact: "upn:unknown", want: "refused"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set := observeUncertainSet(t, tc.globalStrict, config.ProfileAssignment{Profile: tc.profile, Match: tc.match})
			subject := tc.subject
			got := set.selectProfile(&subject, resolveIdentity(&subject, tc.unresolved), profileSubjectVerified, tc.connector, "agt-00000000000000bb")
			if !slices.Contains(got.Unproven, tc.fact) {
				t.Fatalf("unproven %v; want %s named: %+v", got.Unproven, tc.fact, got)
			}
			if name, present := guardrailProfileTelemetryFromDecision(got).Name.Get(); present {
				t.Fatalf("an uncertain decision recorded the inferred profile %q", name)
			}
			api := &APIServer{}
			api.guardrailProfiles.set.Store(set)
			ctx := context.WithValue(t.Context(), resolvedGuardrailProfileKey{}, &resolvedGuardrailProfile{decision: got, set: set})
			_, hookRefused := api.refuseProfileHook(ctx, connector.HookProfile{}, tc.connector,
				agentHookRequest{ConnectorName: tc.connector, HookEventName: "pre_tool_use"}, nil, nil)
			r := httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool", nil).WithContext(ctx)
			inspectRefused := api.refuseProfileInspect(httptest.NewRecorder(), r, "/api/v1/inspect/tool", "inspect-tool-block", "tool")
			proxyRefused := refuseProfileProxy(httptest.NewRecorder(), r)
			if tc.want == "refused" {
				if got.Refused == "" || got.Uncertain != "" || !hookRefused || !inspectRefused || !proxyRefused {
					t.Fatalf("a candidate blocks under strict: %+v (hook %t, inspect %t, proxy %t); want refused everywhere",
						got, hookRefused, inspectRefused, proxyRefused)
				}
				return
			}
			if got.Refused != "" || hookRefused || inspectRefused || proxyRefused {
				t.Fatalf("no candidate is strict: %+v (hook %t, inspect %t, proxy %t); want the strictest candidate applied, not refused",
					got, hookRefused, inspectRefused, proxyRefused)
			}
			if !strings.Contains(got.Uncertain, "unconfirmed") || !strings.Contains(got.Uncertain, "profile explain --user "+p.id) {
				t.Fatalf("the applied decision does not name the missing fact and the explain command: %q", got.Uncertain)
			}
			cfg := set.profileConfig(got.Name)
			if mode := hookModeForConfig(cfg, tc.connector); mode != tc.want {
				t.Fatalf("hook mode %q under %q; want %s, the strictest candidate's own", mode, got.Name, tc.want)
			}
			if mode := inspectMode(cfg, tc.connector); mode != tc.want {
				t.Fatalf("inspect mode %q under %q; want %s", mode, got.Name, tc.want)
			}
			floor, _, err := set.base.SandboxManagedFloor(got.Name)
			if err != nil || tc.sandbox != slices.Contains(floor.RequiredFor, "codex") {
				t.Fatalf("sandbox floor %+v (%v) under %q; want the candidate's sandbox limits kept: %t", floor, err, got.Name, tc.sandbox)
			}
		})
	}
}

// strictRulePack names the built-in strict pack by name or as a v8
// rule_pack_dir, and nothing else.
func TestStrictRulePackIsTheBuiltInStrictPack(t *testing.T) {
	for _, tc := range []struct {
		pack, dir string
		want      bool
	}{
		{pack: "strict", want: true},
		{dir: "/etc/defenseclaw/policies/guardrail/strict", want: true},
		{dir: "/etc/defenseclaw/policies/guardrail/strict/", want: true},
		{pack: "default"},
		{pack: "strict-custom"},
		{dir: "/etc/defenseclaw/policies/guardrail/default"},
		{},
	} {
		cfg := &config.Config{}
		cfg.Guardrail.RulePack, cfg.Guardrail.RulePackDir = tc.pack, tc.dir
		if got := strictRulePack(cfg, "codex"); got != tc.want {
			t.Errorf("strictRulePack(rule_pack %q, rule_pack_dir %q) = %t; want %t", tc.pack, tc.dir, got, tc.want)
		}
	}
}

// The hook path of the same review: an unresolved 1.0.3 agents entry
// (the ledger cannot prove its owner) leaves the hook in the mode of the
// strictest candidate, observe or action, with the agent fact named; only
// an entry under strict refuses.
func TestUnresolvedLegacyAgentEntryHookUsesTheStrictestCandidateMode(t *testing.T) {
	for _, tc := range []struct{ entryProfile, want string }{
		{"legacy-watch", "observe"}, {"action", "action"}, {"strict", "refused"},
	} {
		t.Run(tc.entryProfile, func(t *testing.T) {
			stubProfileSources(t)
			legacy := agentidentity.LegacyAgentID(legacyBridgeInputs("alice@corp.example"))
			corp := agentidentity.AgentID(legacyBridgeInputs("alice@corp.example"))
			legacyBridgeDerives(t, legacyBridgeInputs("alice@corp.example"))
			previous := profileAgentLedger
			t.Cleanup(func() { profileAgentLedger = previous })
			profileAgentLedger = func(inventory.AgentIdentityFilter) ([]inventory.AgentIdentityRecord, bool) { return nil, false }
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "observe"
			strictTier(t, cfg, config.GuardrailProfile{}, "strict")
			cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
				"watch": {Mode: "observe"}, "legacy-watch": {Mode: "observe", BlockAt: "LOW"},
				"action": {Mode: "action"}, "strict": {Mode: "action", RulePack: "strict"},
			}
			cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{{Profile: tc.entryProfile, Match: config.ProfileMatch{Agents: []string{legacy}}}}
			cfg.Guardrail.DefaultProfile = "watch"
			api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg)
			profileAgentSource = func(context.Context) (string, bool) { return corp, true }
			ctx := context.WithValue(t.Context(), testVerifiedSubjectKey{}, profileSubject{UserID: "70001", UserName: "alice"})
			ctx = api.withGuardrailProfileDecision(ctx, "codex")
			got, mode, refused := api.resolveProfile(ctx), api.agentHookMode(ctx, "codex"), api.profileRefused(ctx, profileSurfacesAll)
			if !slices.Equal(got.Unproven, []string{"agent:unknown"}) {
				t.Fatalf("unproven %v; want the agent fact named: %+v", got.Unproven, got)
			}
			if tc.want == "refused" {
				if refused == "" || !strings.Contains(refused, "pre-upgrade agent identity") {
					t.Fatalf("a strict unresolved entry: %+v, refusal %q; want refused naming the agent fact", got, refused)
				}
				return
			}
			if refused != "" || mode != tc.want || !strings.Contains(got.Uncertain, "pre-upgrade agent identity") {
				t.Fatalf("an unresolved %s entry: %+v, mode %q, refusal %q; want mode %s with the agent fact named", tc.entryProfile, got, mode, refused, tc.want)
			}
		})
	}
}
