// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strconv"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/agentidentity"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

// r2BridgeConfig assigns the profiles of assignments in order, over a
// strict (action, block_at LOW) and a watch (observe) profile; the default
// is the weaker watch.
func r2BridgeConfig(assignments ...config.ProfileAssignment) *config.Config {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"strict": {Mode: "action", BlockAt: "LOW"}, "watch": {Mode: "observe"},
	}
	cfg.Guardrail.ProfileAssignments = assignments
	cfg.Guardrail.DefaultProfile = "watch"
	return cfg
}

// Loop round 2, finding 2: no ledger record, a sole one included, proves
// whose agent a 1.0.3 agents entry names (GAP-0337), and such an unproven
// entry never resolves to a weaker default_profile. The account the sole
// record names, whose strict 1.0.3 assignment the release matched, is
// refused with the unproven fact named; strict is only a diagnostic candidate.
// Before, it fell to the weaker default. A namesake the record names is
// refused too, and an account the entry cannot name keeps its own match.
func TestSoleLegacyRowNeverResolvesToAWeakerDefault(t *testing.T) {
	stubProfileSources(t)
	legacy := agentidentity.LegacyAgentID(legacyBridgeInputs("alice@corp.example"))
	corp, lab := agentidentity.AgentID(legacyBridgeInputs("alice@corp.example")), agentidentity.AgentID(legacyBridgeInputs("alice@lab.example"))
	hook := func(t *testing.T, cfg *config.Config, agent string, subject profileSubject) (profileDecision, string) {
		t.Helper()
		api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg)
		profileAgentSource = func(context.Context) (string, bool) { return agent, true }
		ctx := context.WithValue(t.Context(), testVerifiedSubjectKey{}, subject)
		ctx = api.withGuardrailProfileDecision(ctx, "codex")
		return api.resolveProfile(ctx), api.agentHookMode(ctx, "codex")
	}
	alice := profileSubject{UserID: "70001", UserName: "alice"}
	failed, unknown := alice, alice
	failed.LookupFailed, unknown.GroupsUnknown = true, true
	entry := config.ProfileAssignment{Profile: "strict", Match: config.ProfileMatch{Agents: []string{legacy}}}
	connector := config.ProfileAssignment{Profile: "watch", Match: config.ProfileMatch{Connectors: []string{"codex"}}}
	withUID := config.ProfileAssignment{Profile: "strict", Match: config.ProfileMatch{Agents: []string{legacy}, Users: []string{"70001"}}}
	for _, tc := range []struct {
		name     string
		recorded string
		agent    string
		subject  profileSubject
		cfg      *config.Config
	}{
		{"the recorded account", "alice@corp.example", corp, alice, r2BridgeConfig(entry)},
		{"the recorded account, a later weaker connector row", "alice@corp.example", corp, alice, r2BridgeConfig(entry, connector)},
		{"the recorded account, directory lookup failed", "alice@corp.example", corp, failed, r2BridgeConfig(entry)},
		{"the recorded account, groups unknown", "alice@corp.example", corp, unknown, r2BridgeConfig(entry)},
		{"the recorded account, the entry also names its uid", "alice@corp.example", corp, alice, r2BridgeConfig(withUID, connector)},
		{"the namesake the record names", "alice@lab.example", lab, alice, r2BridgeConfig(entry, connector)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			records := []inventory.AgentIdentityRecord{legacyBridgeRecord(legacy, tc.recorded)}
			legacyBridgeLedger(t, &records)
			got, mode := hook(t, tc.cfg, tc.agent, tc.subject)
			if got.Name != "strict" || got.Match != profileMatchDefaultLookupFailed || mode != "action" {
				t.Errorf("profile %+v, mode %q; want strict (action) as default_lookup_failed, never the weaker default", got, mode)
			}
		})
	}
	t.Run("another account's agent", func(t *testing.T) {
		bob := agentidentity.AgentID(agentidentity.Inputs{
			MachineHash: agentidentity.MachineHash("0123456789abcdef0123456789abcdef"), UserID: "70002",
			Connector: "codex", InstallFP: "/home/bob/.codex", Account: "bob@corp.example",
		})
		records := []inventory.AgentIdentityRecord{legacyBridgeRecord(legacy, "alice@corp.example"), {
			AgentID: bob, UserID: "70002", UserName: "bob@corp.example", Connector: "codex",
			InstallFP: "/home/bob/.codex", MachineHash: agentidentity.MachineHash("0123456789abcdef0123456789abcdef"),
		}}
		legacyBridgeLedger(t, &records)
		got, mode := hook(t, r2BridgeConfig(entry, connector), bob, profileSubject{UserID: "70002", UserName: "bob"})
		if got.Name != "watch" || got.Match != profileMatchConnector || mode != "observe" {
			t.Errorf("profile %+v, mode %q; want its own connector assignment", got, mode)
		}
	})
	t.Run("the entry names the current identity", func(t *testing.T) {
		records := []inventory.AgentIdentityRecord{legacyBridgeRecord(legacy, "alice@corp.example")}
		legacyBridgeLedger(t, &records)
		rebound := config.ProfileAssignment{Profile: "strict", Match: config.ProfileMatch{Agents: []string{corp}}}
		got, mode := hook(t, r2BridgeConfig(rebound, connector), corp, alice)
		if got.Name != "strict" || got.Match != profileMatchAgent || mode != "action" {
			t.Errorf("profile %+v, mode %q; want its rebound agent assignment", got, mode)
		}
	})
}

// Loop round 2, finding 5: the 1.0.3 identity of a request's agent is
// derived with the request. A process-wide map of derivations, capped at
// 4,096 identities, dropped the derivation of an agent first seen past the
// cap; with the agent ledger unreadable, an exact current-identity entry
// then skipped an earlier strict assignment written for that agent's 1.0.3
// identity and the weaker watch applied. Now the earlier entry holds: the
// request gets the strictest profile that may apply.
func TestLegacyOwnershipCheckSurvivesManyIdentitiesWithAnUnreadableLedger(t *testing.T) {
	agentIdentityTestSetup(t)
	stubProfileSources(t)
	profileAgentSource = requestAgentIdentity
	restoreAccount := agentIdentityAccountName
	t.Cleanup(func() { agentIdentityAccountName = restoreAccount })
	agentIdentityAccountName = func(id string) string {
		if id == "70001" {
			return "alice@corp.example"
		}
		return "u" + id + "@corp.example"
	}
	aliceHome := t.TempDir()
	peer := func(uid int) context.Context {
		home := "/home/u"
		if uid == 70001 {
			home = aliceHome
		}
		return withManagedHookPeer(t.Context(), managedHookPeer{UID: uid, Name: agentIdentityAccountName(strconv.Itoa(uid)), Home: home})
	}
	for uid := 80000; uid < 80000+5000; uid++ {
		if resolveHookAgentIdentity(peer(uid), agentHookRequest{ConnectorName: "codex"}).ID == "" {
			t.Fatal("the hook path derived no agent identity")
		}
	}
	facts := resolveHookAgentIdentity(peer(70001), agentHookRequest{ConnectorName: "codex"})
	legacy := agentidentity.LegacyAgentID(agentidentity.Inputs{
		MachineHash: facts.MachineHash, UserID: facts.UserID, Account: "alice@corp.example",
		Connector: facts.Connector, InstallFP: facts.InstallFP,
	})
	if facts.ID == "" || legacy == "" || legacy == facts.ID {
		t.Fatalf("identity %q, legacy %q: want two identities", facts.ID, legacy)
	}
	previous := profileAgentLedger
	t.Cleanup(func() { profileAgentLedger = previous })
	profileAgentLedger = func(inventory.AgentIdentityFilter) ([]inventory.AgentIdentityRecord, bool) { return nil, false }
	cfg := r2BridgeConfig(
		config.ProfileAssignment{Profile: "strict", Match: config.ProfileMatch{Agents: []string{legacy}}},
		config.ProfileAssignment{Profile: "watch", Match: config.ProfileMatch{Agents: []string{facts.ID}}},
	)
	api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg)
	ctx := context.WithValue(peer(70001), testVerifiedSubjectKey{}, profileSubject{UserID: "70001", UserName: "alice"})
	ctx = api.withGuardrailProfileDecision(ctx, "codex")
	if got, mode := api.resolveProfile(ctx), api.agentHookMode(ctx, "codex"); got.Name != "strict" || got.Match != profileMatchDefaultLookupFailed || mode != "action" {
		t.Errorf("after 5000 other identities: profile %+v, mode %q; want strict (action) as default_lookup_failed", got, mode)
	}
}
