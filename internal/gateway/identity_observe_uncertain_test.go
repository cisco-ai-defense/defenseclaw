// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/agentidentity"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

// observeUncertainSet is a profile set whose default, watch, only
// observes, with candidate profiles that observe or may block in each way a
// profile can: by its mode, by a per-connector mode, or by a sandbox
// section.
func observeUncertainSet(t *testing.T, assignments ...config.ProfileAssignment) *guardrailProfileSet {
	t.Helper()
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"watch":        {Mode: "observe"},
		"legacy-watch": {Mode: "observe", BlockAt: "LOW"},
		"strict":       {Mode: "action", BlockAt: "LOW"},
		"codex-action": {Mode: "observe", Connectors: map[string]config.PerConnectorGuardrailConfig{"codex": {Mode: "action"}}},
		"sandboxed":    {Mode: "observe", Sandbox: &config.OpenShellAdminConfig{RequiredFor: []string{"codex"}}},
	}
	cfg.Guardrail.ProfileAssignments = assignments
	cfg.Guardrail.DefaultProfile = "watch"
	set, err := newGuardrailProfileSet(cfg, nil, true)
	if err != nil || set == nil {
		t.Fatalf("profile set: %v", err)
	}
	return set
}

// Review of r104 Q-identity (continuation 3, loop round 3): after a 1.0.3
// upgrade, an agents entry whose owner the migration map has not proven
// (the map not written yet, or pending for an unnamed account) made the
// agent fact unproven, and the request was refused in action mode although
// the entry's profile and the default both only observe. No answer of the
// missing fact could block the request, and the 1.0.3 release observed it.
// A decision that needs an unproven fact is refused only when a profile
// that may apply blocks the request: its mode or its per-connector mode is
// action, or the candidates' sandbox sections differ. Otherwise it is
// observed under their combination with the missing facts named
// (Uncertain), for every kind of unproven fact.
func TestUncertainDecisionAmongObserveProfilesIsObservedNotRefused(t *testing.T) {
	p := identityTestPlatforms[0]
	const legacy = "agt-00000000000000aa"
	unresolved := func(entry string) bool { return entry == legacy }
	proven := identityTestSubject(p, p.providers[1], stateProven, false)
	groupsUnknown := identityTestSubject(p, p.providers[1], stateGroupsUnknown, false)
	upnUnknown := proven
	upnUnknown.upnUnproven = true
	for _, tc := range []struct {
		name       string
		subject    profileSubject
		unresolved func(string) bool
		match      config.ProfileMatch
		profile    string
		connector  string
		fact       string
		refused    bool
	}{
		{name: "agent entry, both observe", subject: proven, unresolved: unresolved, match: config.ProfileMatch{Agents: []string{legacy}},
			profile: "legacy-watch", connector: "codex", fact: "agent:unknown"},
		{name: "agent entry blocks", subject: proven, unresolved: unresolved, match: config.ProfileMatch{Agents: []string{legacy}},
			profile: "strict", connector: "codex", fact: "agent:unknown", refused: true},
		{name: "agent entry blocks for this connector", subject: proven, unresolved: unresolved, match: config.ProfileMatch{Agents: []string{legacy}},
			profile: "codex-action", connector: "codex", fact: "agent:unknown", refused: true},
		{name: "agent entry blocks for another connector only", subject: proven, unresolved: unresolved, match: config.ProfileMatch{Agents: []string{legacy}},
			profile: "codex-action", connector: "hermes", fact: "agent:unknown"},
		{name: "agent entry has a sandbox section", subject: proven, unresolved: unresolved, match: config.ProfileMatch{Agents: []string{legacy}},
			profile: "sandboxed", connector: "codex", fact: "agent:unknown", refused: true},
		{name: "groups unknown, both observe", subject: groupsUnknown, match: config.ProfileMatch{Groups: []string{p.group}},
			profile: "legacy-watch", connector: "codex", fact: "groups:unknown"},
		{name: "groups unknown, group profile blocks", subject: groupsUnknown, match: config.ProfileMatch{Groups: []string{p.group}},
			profile: "strict", connector: "codex", fact: "groups:unknown", refused: true},
		{name: "UPN unknown, both observe", subject: upnUnknown, match: config.ProfileMatch{Users: []string{"alice@corp.example"}},
			profile: "legacy-watch", connector: "codex", fact: "upn:unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set := observeUncertainSet(t, config.ProfileAssignment{Profile: tc.profile, Match: tc.match})
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
			if tc.refused {
				if got.Refused == "" || got.Uncertain != "" || !hookRefused || !inspectRefused || !proxyRefused {
					t.Fatalf("a candidate profile blocks: %+v (hook %t, inspect %t, proxy %t); want refused everywhere",
						got, hookRefused, inspectRefused, proxyRefused)
				}
				return
			}
			if got.Refused != "" || hookRefused || inspectRefused || proxyRefused {
				t.Fatalf("every candidate only observes: %+v (hook %t, inspect %t, proxy %t); want observed, not refused",
					got, hookRefused, inspectRefused, proxyRefused)
			}
			if !strings.Contains(got.Uncertain, "unconfirmed") || !strings.Contains(got.Uncertain, "profile explain --user "+p.id) {
				t.Fatalf("the observed decision does not name the missing fact and the explain command: %q", got.Uncertain)
			}
			cfg := set.profileConfig(got.Name)
			if mode := hookModeForConfig(cfg, tc.connector); mode != "observe" {
				t.Fatalf("hook mode %q under %q; want observe", mode, got.Name)
			}
			if mode := inspectMode(cfg, tc.connector); mode != "observe" {
				t.Fatalf("inspect mode %q under %q; want observe", mode, got.Name)
			}
		})
	}
}

// The hook path of the same review: an unresolved 1.0.3 agents entry
// (the ledger cannot prove its owner) whose profile and the default both
// observe leaves the hook in observe mode, not refused; a strict entry
// still refuses.
func TestUnresolvedLegacyAgentEntryAmongObserveProfilesObservesTheHook(t *testing.T) {
	for _, entryProfile := range []string{"legacy-watch", "strict"} {
		t.Run(entryProfile, func(t *testing.T) {
			stubProfileSources(t)
			legacy := agentidentity.LegacyAgentID(legacyBridgeInputs("alice@corp.example"))
			corp := agentidentity.AgentID(legacyBridgeInputs("alice@corp.example"))
			legacyBridgeDerives(t, legacyBridgeInputs("alice@corp.example"))
			previous := profileAgentLedger
			t.Cleanup(func() { profileAgentLedger = previous })
			profileAgentLedger = func(inventory.AgentIdentityFilter) ([]inventory.AgentIdentityRecord, bool) { return nil, false }
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "observe"
			cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
				"watch": {Mode: "observe"}, "legacy-watch": {Mode: "observe", BlockAt: "LOW"}, "strict": {Mode: "action"},
			}
			cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{{Profile: entryProfile, Match: config.ProfileMatch{Agents: []string{legacy}}}}
			cfg.Guardrail.DefaultProfile = "watch"
			api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg)
			profileAgentSource = func(context.Context) (string, bool) { return corp, true }
			ctx := context.WithValue(t.Context(), testVerifiedSubjectKey{}, profileSubject{UserID: "70001", UserName: "alice"})
			ctx = api.withGuardrailProfileDecision(ctx, "codex")
			got, mode, refused := api.resolveProfile(ctx), api.agentHookMode(ctx, "codex"), api.profileRefused(ctx)
			if !slices.Equal(got.Unproven, []string{"agent:unknown"}) {
				t.Fatalf("unproven %v; want the agent fact named: %+v", got.Unproven, got)
			}
			if entryProfile == "strict" {
				if refused == "" || !strings.Contains(refused, "pre-upgrade agent identity") {
					t.Fatalf("a strict unresolved entry: %+v, refusal %q; want refused naming the agent fact", got, refused)
				}
				return
			}
			if refused != "" || mode != "observe" || !strings.Contains(got.Uncertain, "pre-upgrade agent identity") {
				t.Fatalf("an observe unresolved entry: %+v, mode %q, refusal %q; want observed with the agent fact named", got, mode, refused)
			}
		})
	}
}
